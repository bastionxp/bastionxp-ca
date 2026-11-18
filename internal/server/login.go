// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/metrics"
	"github.com/bastionxp/bastionxp-ca/internal/oidc"
	"github.com/bastionxp/bastionxp-ca/internal/policy"
	"github.com/bastionxp/bastionxp-ca/internal/token"
)

// This file is the login verifier: a person logs in with the company's
// identity provider (OIDC), in their browser. A login is a trip of the
// person's browser:
//
//	program on the person's machine      listens on 127.0.0.1:<port>
//	  │ opens the browser at
//	  ▼
//	GET /v1/oidc/login         (here)    remember what was asked for
//	  │ redirect
//	  ▼
//	the identity provider                the person logs in
//	  │ redirect
//	  ▼
//	GET /v1/oidc/callback      (here)    who is it? may they have it?
//	  │ redirect, with a one-time token
//	  ▼
//	http://127.0.0.1:<port>/...          the program takes the token
//
// The program then uses the token at the normal sign endpoints. So a
// certificate for a person who logged in takes the same road as one for a
// token made on the CA machine. Nothing is signed in this file.
//
// errLoginFailed is what a provider returns when the person's login did
// not succeed: they have to start again.
var errLoginFailed = errors.New("the login failed")

// loginProvider is one way of logging in with a browser.
type loginProvider interface {
	// authorizeURL is where to send the browser.
	authorizeURL(ctx context.Context, redirectURI, state, nonce, verifier string) (string, error)
	// identify turns the code the provider sent back into the person.
	identify(ctx context.Context, code, redirectURI, nonce, verifier string) (policy.Identity, error)
}

// loginFlow is one provider, with its addresses.
type loginFlow struct {
	source       string // "oidc"
	displayName  string // for messages: "your identity provider"
	loginPath    string
	callbackPath string
	provider     loginProvider
}

// oidcProvider adapts the OIDC client.
type oidcProvider struct{ client *oidc.Client }

func (p oidcProvider) authorizeURL(ctx context.Context, redirectURI, state, nonce, verifier string) (string, error) {
	return p.client.AuthorizeURL(ctx, redirectURI, state, nonce, verifier)
}

func (p oidcProvider) identify(ctx context.Context, code, redirectURI, nonce, verifier string) (policy.Identity, error) {
	id, err := p.client.Login(ctx, code, redirectURI, nonce, verifier)
	if errors.Is(err, oidc.ErrLoginFailed) {
		return policy.Identity{}, fmt.Errorf("%w: %v", errLoginFailed, err)
	}
	return id, err
}

// keyTokenValidity is how long a token from a login lasts when it is
// tied to a key. The program that asked for it uses it within a second.
const keyTokenValidity = time.Minute

// maxLoginParamLength limits the size of what a browser can send us.
const maxLoginParamLength = 512

// isSetUp answers the request with an error if this login is not
// configured on this CA.
func (s *Server) isSetUp(w http.ResponseWriter, flow *loginFlow) bool {
	if flow == nil || s.access.Load() == nil || s.publicURL == "" {
		name := "this kind of login"
		if flow != nil {
			name = "login with " + flow.displayName
		}
		http.Error(w, "The "+name+" is not set up on this CA.", http.StatusNotFound)
		return false
	}
	return true
}

// redirectURI is where the provider sends the browser after the login. It
// must be the callback address registered at the provider.
func (s *Server) redirectURI(flow *loginFlow) string {
	return s.publicURL + flow.callbackPath
}

// The secrets of one login, derived from its ID: the OIDC nonce, and the
// PKCE verifier, which must never travel through the browser.
func (s *Server) loginSecrets(login *token.Login) (nonce, verifier string) {
	return s.tokens.Derive("oidc-nonce", login.ID), s.tokens.Derive("pkce-verifier", login.ID)
}

// loopbackCallback checks the address a token will be sent to at the end
// of a login. This check is what keeps tokens on the machine of the
// person who logged in.
//
// Only http://127.0.0.1:<port>/... is accepted: an address that always
// means "this same machine". If any other address were accepted, someone
// could send a person a link to this CA that, after an honest login,
// delivers that person's token to a server of their choice.
func loopbackCallback(raw string) (*url.URL, bool) {
	if len(raw) > maxLoginParamLength {
		return nil, false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, false
	}
	// Plain http is right here: the connection never leaves the machine.
	if u.Scheme != "http" || u.User != nil || u.Fragment != "" {
		return nil, false
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || port == "" {
		return nil, false
	}
	// Compare the text, not a looked-up address: a name such as
	// "localhost" or "127.0.0.1.example.com" could point anywhere.
	if host != "127.0.0.1" {
		return nil, false
	}
	return u, true
}

// sendResult ends a login: it sends the browser to the callback address
// with either a token or an error message for the waiting program.
func sendResult(w http.ResponseWriter, r *http.Request, login *token.Login, oneTime, errMessage string) {
	// The callback was checked by loopbackCallback before it was signed
	// into the login, so it parses.
	callback, err := url.Parse(login.Callback)
	if err != nil {
		http.Error(w, "The login cannot be finished. Run the command again.", http.StatusBadRequest)
		return
	}
	query := callback.Query()
	query.Set(api.ResultState, login.ClientState)
	if errMessage != "" {
		query.Set(api.ResultError, errMessage)
	} else {
		query.Set(api.ResultToken, oneTime)
	}
	callback.RawQuery = query.Encode()

	// The address holds a token. Keep it out of caches and out of the
	// "Referer" header of whatever the browser loads next.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, callback.String(), http.StatusFound)
}

// handleLogin returns the handler where a login starts. It notes what
// the person asks for and sends the browser on to the provider.
func (s *Server) handleLogin(flow *loginFlow) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { s.startLogin(w, r, flow) }
}

func (s *Server) startLogin(w http.ResponseWriter, r *http.Request, flow *loginFlow) {
	if !s.isSetUp(w, flow) {
		return
	}
	query := r.URL.Query()

	// Until the callback is known to be good there is nowhere safe to
	// send an error, so these two are shown in the browser.
	if _, ok := loopbackCallback(query.Get(api.LoginCallback)); !ok {
		http.Error(w, "This login link is not valid: the callback must be an address on your own machine (http://127.0.0.1:<port>/...).", http.StatusBadRequest)
		return
	}
	clientState := query.Get(api.LoginState)
	if clientState == "" || len(clientState) > maxLoginParamLength {
		http.Error(w, "This login link is not valid: the state is missing.", http.StatusBadRequest)
		return
	}

	login := token.Login{
		Provider:       flow.source,
		Callback:       query.Get(api.LoginCallback),
		ClientState:    clientState,
		Template:       query.Get(api.LoginProfile),
		Names:          query[api.LoginName],
		Subject:        query.Get(api.LoginSubject),
		KeyFingerprint: query.Get(api.LoginKey),
	}

	// From here on, errors go to the program that is waiting.
	var ok bool
	if login.Template, ok = s.ownProfile(flow.source, login.Template, query.Get(api.LoginKind)); !ok {
		sendResult(w, r, &login, "", "the profile must be tls-server, tls-client, tls-device, ssh-user, ssh-host or one configured on the CA")
		return
	}
	if validFor := query.Get(api.LoginValidFor); validFor != "" {
		var err error
		login.ValidFor, err = time.ParseDuration(validFor)
		if err != nil {
			sendResult(w, r, &login, "", `invalid validity for the token: use a duration such as "10m" or "1h"`)
			return
		}
	}

	// The provider hands the "state" back unchanged with the result. We
	// put the whole signed login in it, so nothing has to be stored here
	// while the person is away.
	signed, err := s.tokens.IssueLogin(login)
	if err != nil {
		s.log.Error("cannot sign a login", "error", err)
		sendResult(w, r, &login, "", "internal error")
		return
	}
	// Read it back for its ID, which the secrets are derived from.
	issued, err := s.tokens.VerifyLogin(signed)
	if err != nil {
		s.log.Error("cannot read back a login", "error", err)
		sendResult(w, r, &login, "", "internal error")
		return
	}
	nonce, verifier := s.loginSecrets(issued)
	address, err := flow.provider.authorizeURL(r.Context(), s.redirectURI(flow), signed, nonce, verifier)
	if err != nil {
		s.log.Error("cannot start a login", "provider", flow.source, "error", err)
		sendResult(w, r, &login, "", "the CA cannot reach "+flow.displayName+", try again later")
		return
	}
	http.Redirect(w, r, address, http.StatusFound)
}

// handleCallback returns the handler where the provider sends the browser
// after the login. It finds out who the person is, decides whether they
// may have what they asked for, and sends a one-time token to the waiting
// program.
func (s *Server) handleCallback(flow *loginFlow) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { s.finishLogin(w, r, flow) }
}

func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, flow *loginFlow) {
	if !s.isSetUp(w, flow) {
		return
	}
	query := r.URL.Query()

	// The state must be a login that we signed ourselves, not long ago,
	// for this provider. Everything in it, above all the callback
	// address, can then be trusted to be what we checked at the start.
	login, err := s.tokens.VerifyLogin(query.Get("state"))
	if err == nil && login.Provider != flow.source {
		err = errors.New("the login was started for " + login.Provider)
	}
	if err != nil {
		s.log.Warn("login callback refused", "provider", flow.source, "error", err, "remote", r.RemoteAddr)
		http.Error(w, "This login is not valid or took too long. Run the command again.", http.StatusBadRequest)
		return
	}

	// The person pressed "Cancel" at the provider.
	if query.Get("error") != "" {
		sendResult(w, r, login, "", "the login at "+flow.displayName+" was cancelled")
		return
	}

	// Verifier: who is asking? The provider tells us.
	nonce, verifier := s.loginSecrets(login)
	id, err := flow.provider.identify(r.Context(), query.Get("code"), s.redirectURI(flow), nonce, verifier)
	if errors.Is(err, errLoginFailed) {
		s.log.Warn("login failed", "provider", flow.source, "error", err, "remote", r.RemoteAddr)
		s.metrics.Login(flow.source, metrics.LoginFailed)
		sendResult(w, r, login, "", "the login at "+flow.displayName+" failed, try again")
		return
	}
	if err != nil {
		s.log.Error("cannot finish a login", "provider", flow.source, "error", err)
		sendResult(w, r, login, "", "the CA cannot finish the login with "+flow.displayName+", try again later")
		return
	}

	oneTime, err := s.tokenFor(id, wantedToken{
		template:       login.Template,
		names:          login.Names,
		subject:        login.Subject,
		validFor:       login.ValidFor,
		keyFingerprint: login.KeyFingerprint,
	}, flow.source, r.RemoteAddr)
	var refused refusedError
	switch {
	case errors.As(err, &refused):
		sendResult(w, r, login, "", refused.message)
	case err != nil:
		sendResult(w, r, login, "", "internal error")
	default:
		sendResult(w, r, login, oneTime, "")
	}
}

// wantedToken is what a person who logged in asks a token for.
type wantedToken struct {
	template       string
	names          []string
	subject        string
	validFor       time.Duration
	keyFingerprint string
}

// refusedError is a token request that the rules do not allow, or that is
// not sound. Its message is for the person.
type refusedError struct{ message string }

func (e refusedError) Error() string { return e.message }

// tokenFor decides whether the person may have the token they ask for and,
// if so, makes it. Every login verifier ends here, so all of them follow
// the same rules. An error is a refusedError, or an internal error.
func (s *Server) tokenFor(id policy.Identity, want wantedToken, source, remote string) (string, error) {
	// The rules as they are now, for the rest of this request.
	rules := s.access.Load()

	// Having an account is not enough. Only people the rules name get
	// anything.
	if !rules.MayLogIn(id) {
		s.log.Warn("login refused: no rule for this person", "provider", source, "login", id.Username, "groups", id.Groups, "remote", remote)
		s.metrics.Login(source, metrics.LoginNoRule)
		return "", refusedError{"the user " + id.Username + " may not use this CA"}
	}

	s.metrics.Login(source, metrics.LoginSuccess)

	// Policy: may this person have what they asked for?
	allowed, err := rules.AuthorizeToken(id, s.ownFor(source), policy.TokenRequest{
		Template: want.template,
		Names:    want.names,
		Subject:  want.subject,
	})
	if err != nil {
		s.log.Warn("token refused", "provider", source, "error", err, "login", id.Username, "remote", remote)
		s.metrics.Refused(metrics.RefusedPolicy)
		return "", refusedError{err.Error()}
	}

	// A token tied to a key is used at once by the program that asked
	// for it, so it can be very short-lived.
	validFor := want.validFor
	if want.keyFingerprint != "" {
		validFor = keyTokenValidity
	}
	oneTime, err := s.tokens.Issue(token.Options{
		Subject:        allowed.Subject,
		Template:       allowed.Template,
		Names:          allowed.Names,
		ValidFor:       validFor,
		CreatedBy:      id.Username,
		KeyFingerprint: want.keyFingerprint,
	})
	if err != nil {
		// Issue refuses requests that are not sound: no names,
		// validity above the maximum, a subject with spaces.
		return "", refusedError{err.Error()}
	}
	// Read the new token back, to learn its ID and expiry time for the log.
	grant, err := s.tokens.Verify(oneTime)
	if err != nil {
		s.log.Error("cannot read back a new token", "error", err)
		return "", err
	}

	s.log.Info("token created",
		"verifier", source,
		"created_by", id.Username,
		"groups", id.Groups,
		"admin", rules.IsAdmin(id),
		"subject", grant.Subject,
		"profile", grant.Template,
		"names", grant.Names,
		"key", grant.KeyFingerprint,
		"token_id", grant.ID,
		"expires", grant.Expires.UTC().Format(time.RFC3339),
		"remote", remote,
	)
	return oneTime, nil
}
