// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package server is the CA's HTTP API.
//
// Endpoints:
//
//	GET  /health         is the server up?
//	POST /v1/x509/sign   sign a TLS certificate; needs a one-time token
//	POST /v1/ssh/sign    sign an SSH certificate; needs a one-time token
//	POST /v1/x509/renew  renew a TLS certificate; needs the current one
//	POST /v1/ssh/renew   renew an SSH host certificate; likewise
//
//	GET  /v1/oidc/login        a browser starts a login with the identity provider
//	GET  /v1/oidc/callback     and the provider sends the browser back here
//
//	the CA's public information (certificates, CRL, OCSP), see public.go
//
//	/acme/...                  the ACME server, see internal/acme
//	/scep                      the SCEP server, see internal/scep
//
// Requests and responses are JSON. Their fields are defined in the api
// package. Errors look like {"error": "what went wrong"}.
//
// Both sign handlers follow the picture in docs/architecture.md:
// verifier, policy, template, CA.
package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/acme"
	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/ldap"
	"github.com/bastionxp/bastionxp-ca/internal/metrics"
	"github.com/bastionxp/bastionxp-ca/internal/oidc"
	"github.com/bastionxp/bastionxp-ca/internal/policy"
	"github.com/bastionxp/bastionxp-ca/internal/scep"
	"github.com/bastionxp/bastionxp-ca/internal/store"
	"github.com/bastionxp/bastionxp-ca/internal/token"
)

// maxBodyBytes limits the size of a request body. A certificate request
// is a few kilobytes, so this is generous.
const maxBodyBytes = 64 * 1024

// Options are what a Server needs. All fields are required, except where
// noted.
type Options struct {
	CA     *ca.CA
	Tokens *token.Verifier
	Store  *store.Store
	Log    *slog.Logger

	// OIDC turns on login with an OpenID Connect identity provider. It
	// needs AccessRules and PublicURL too. Without them, the login
	// endpoints answer "not set up".
	OIDC        *oidc.Client
	AccessRules *policy.Access
	// PublicURL is the address browsers use to reach this server,
	// e.g. "https://ca.example.com:8443".
	PublicURL string
	// LDAP turns on login with a username and password checked against
	// the company's directory. It needs AccessRules too.
	LDAP *ldap.Client
	// LoginProfiles are the profiles each login verifier ("oidc",
	// "ldap") gives people for themselves.
	LoginProfiles map[string]policy.Own

	// ACME is the handler of the ACME server (internal/acme). Optional:
	// without it there is no ACME.
	ACME http.Handler

	// SCEPRA is the SCEP server's own key and certificate (internal/scep).
	// Optional: without it there is no SCEP.
	SCEPRA *scep.RA
	// SCEPStatic lets devices enroll with a shared challenge password.
	// Optional; see scep_static.go.
	SCEPStatic *SCEPStatic

	// Metrics counts what the server does. Optional.
	Metrics *metrics.CA
}

// Server holds what the HTTP handlers need. Create one with New.
type Server struct {
	ca     *ca.CA
	tokens *token.Verifier
	store  *store.Store
	log    *slog.Logger
	// The browser login, nil when not configured. See login.go.
	oidcFlow *loginFlow
	// The directory for login with a password, nil when not configured.
	// See ldap_login.go.
	ldap *ldap.Client
	// access decides what people who logged in may have. It can be replaced while the server runs (configuration
	// reload); each request takes it once, at its start.
	access    atomic.Pointer[policy.Access]
	publicURL string
	acme      http.Handler
	scepRA    *scep.RA
	static    *scepStatic
	metrics   *metrics.CA
	// own are the profiles each login verifier gives people for
	// themselves, by source ("oidc", "ldap").
	own map[string]policy.Own
	// revocations caches signed CRL and OCSP answers; see revcache.go.
	revocations revocationCache
}

// New returns a Server. Call Handler to get something to serve.
func New(opts Options) *Server {
	srv := &Server{
		ca:        opts.CA,
		tokens:    opts.Tokens,
		store:     opts.Store,
		log:       opts.Log,
		publicURL: strings.TrimRight(opts.PublicURL, "/"),
		acme:      opts.ACME,
		scepRA:    opts.SCEPRA,
		static:    newSCEPStatic(opts.SCEPStatic),
		ldap:      opts.LDAP,
		metrics:   opts.Metrics,
	}
	srv.access.Store(opts.AccessRules)
	srv.own = opts.LoginProfiles
	if opts.OIDC != nil {
		srv.oidcFlow = &loginFlow{source: "oidc", displayName: "your identity provider",
			loginPath: api.OIDCLoginPath, callbackPath: api.OIDCCallbackPath, provider: oidcProvider{opts.OIDC}}
	}
	return srv
}

// SetAccessRules replaces what people who log in may have. Requests that
// are being answered finish with the old rules.
func (s *Server) SetAccessRules(rules *policy.Access) {
	s.access.Store(rules)
}

// Handler returns the HTTP handler with all routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+api.HealthPath, s.handleHealth)
	mux.HandleFunc("POST "+api.SignX509Path, s.handleSignX509)
	mux.HandleFunc("POST "+api.SignSSHPath, s.handleSignSSH)
	mux.HandleFunc("POST "+api.RenewX509Path, s.handleRenewX509)
	mux.HandleFunc("POST "+api.RenewSSHPath, s.handleRenewSSH)
	s.addPublicRoutes(mux) // see public.go
	mux.HandleFunc("GET "+api.OIDCLoginPath, s.handleLogin(s.oidcFlow))
	mux.HandleFunc("GET "+api.OIDCCallbackPath, s.handleCallback(s.oidcFlow))
	mux.HandleFunc("POST "+api.LDAPLoginPath, s.handleLDAPLogin)
	if s.acme != nil {
		// Everything below /acme/ belongs to the ACME server.
		mux.Handle(acme.PathPrefix, s.acme)
	}
	if s.scepRA != nil {
		// The SCEP server only speaks the protocol. Who may have which
		// certificate is decided here, by issueForSCEP.
		mux.Handle(scep.Path, scep.New(scep.Options{
			RA:      s.scepRA,
			CACerts: append(s.ca.Chain(), s.ca.RootCert()),
			Issue:   s.issueForSCEP,
			Renew:   s.renewForSCEP,
			Lookup:  s.lookupForSCEP,
			Log:     s.log,
		}))
	}
	return s.logRequests(s.ocspFirst(mux))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// The helpers below are shared by the sign handlers. Each one that takes
// the ResponseWriter sends the error response itself and returns false,
// so the handler only has to stop.

// verifyToken checks the token in the Authorization header.
func (s *Server) verifyToken(w http.ResponseWriter, r *http.Request) (*token.Grant, bool) {
	grant, err := s.tokens.Verify(bearerToken(r))
	if err != nil {
		// The detail goes to the log only. The requester does not need
		// to learn why exactly a token was refused.
		s.log.Warn("token refused", "error", err, "remote", r.RemoteAddr)
		s.metrics.Refused(metrics.RefusedToken)
		writeError(w, http.StatusUnauthorized, "missing, invalid or expired token")
		return nil, false
	}
	return grant, true
}

// useToken marks the token as used. From then on it is spent, even if
// signing fails. Handlers call this right before signing, so that two
// requests with the same token can never both get a certificate.
func (s *Server) useToken(w http.ResponseWriter, r *http.Request, grant *token.Grant) bool {
	err := s.store.UseToken(r.Context(), grant.ID, grant.Expires)
	if errors.Is(err, store.ErrTokenUsed) {
		s.log.Warn("token used twice", "token_id", grant.ID, "remote", r.RemoteAddr)
		s.metrics.Refused(metrics.RefusedUsed)
		writeError(w, http.StatusUnauthorized, "this token was already used")
		return false
	}
	if err != nil {
		s.log.Error("cannot record token use", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return false
	}
	return true
}

// checkKey makes sure a token that is tied to one key is used for that
// key. fingerprint is the one of the key in the request.
func (s *Server) checkKey(w http.ResponseWriter, r *http.Request, grant *token.Grant, fingerprint string) bool {
	if grant.KeyFingerprint == "" || grant.KeyFingerprint == fingerprint {
		return true
	}
	s.log.Warn("request refused: token is for another key", "token_id", grant.ID, "remote", r.RemoteAddr)
	s.metrics.Refused(metrics.RefusedWrongKey)
	writeError(w, http.StatusForbidden, "not allowed: this token was made for another key")
	return false
}

// verifierName says, for the log, how the requester was checked: "login"
// if the token came from a login with the identity provider ("created_by"
// then names the person), "token" if an administrator made it on the CA
// machine.
// issuedVerifier is verifierName, but "scep" for a certificate that came
// by SCEP, for the metrics.
func issuedVerifier(grant *token.Grant, protocol string) string {
	if protocol == "scep" {
		return "scep"
	}
	return verifierName(grant)
}

func verifierName(grant *token.Grant) string {
	if grant.CreatedBy != "" {
		return "login"
	}
	return "token"
}

// readJSON decodes the request body into dest. Unknown fields are an
// error, so a typo in a field name is not silently ignored.
func readJSON(w http.ResponseWriter, r *http.Request, dest any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// parseValidity reads the "validity" field of a request. Empty means
// zero, which the CA understands as "use the template's default".
func parseValidity(text string) (time.Duration, error) {
	if text == "" {
		return 0, nil
	}
	validity, err := time.ParseDuration(text)
	if err != nil {
		return 0, errors.New(`invalid validity: use a duration such as "24h" or "720h"`)
	}
	return validity, nil
}

// bearerToken returns the token from the "Authorization: Bearer <token>"
// header, or "" if there is none.
func bearerToken(r *http.Request) string {
	scheme, value, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(value)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The status line is already sent, so there is nothing useful to do
	// with an error here. It means the client went away.
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, api.Error{Error: message})
}

// logRequests writes one log line per request.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		s.metrics.Request(routeOf(r), recorder.status, time.Since(start))
		s.log.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.status,
			"duration", time.Since(start).String(),
			"remote", r.RemoteAddr,
		)
	})
}

// statusRecorder remembers the status code a handler sends, for the log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// routeOf names the route a request took, for the metrics: the pattern
// that matched, never the address itself, which may hold serial numbers.
// The mux sets the pattern on the request.
func routeOf(r *http.Request) string {
	switch {
	case r.Pattern != "":
		return r.Pattern
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, ca.OCSPPath+"/"):
		return "GET " + ca.OCSPPath + "/{request}"
	default:
		return "other"
	}
}

// ownProfile resolves the profile of a login request: the one asked for,
// or, when none is, the one the login verifier gives people for
// themselves of that kind ("ssh" or "x509"). ok is false for an unknown
// profile or kind.
func (s *Server) ownProfile(source, profile, kind string) (string, bool) {
	if profile == "" {
		own := s.ownFor(source)
		switch kind {
		case "ssh":
			profile = own.SSHProfile
		case "x509":
			profile = own.X509Profile
		}
	}
	_, isX509 := s.ca.X509Template(profile)
	_, isSSH := s.ca.SSHTemplate(profile)
	return profile, profile != "" && (isX509 || isSSH)
}

// ownFor returns the profiles a login verifier gives people for
// themselves: the configured ones, or the defaults, ssh-user and
// tls-client.
func (s *Server) ownFor(source string) policy.Own {
	own := s.own[source]
	if own.SSHProfile == "" {
		own.SSHProfile = ca.SSHUser.Name
	}
	if own.X509Profile == "" {
		own.X509Profile = ca.TLSClient.Name
	}
	return own
}
