// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package acme is an ACME server (RFC 8555): the protocol that certbot,
// acme.sh, lego, Caddy and others use to get TLS certificates by
// themselves. It is the ACME verifier of the CA.
//
// How a client gets a certificate:
//
//  1. It creates an account, which is nothing more than a public key.
//     Every later request is signed with that key.
//  2. It places an order for a list of host names.
//  3. For each name the server creates an authorization with challenges,
//     around a random token. The client answers one of them with the
//     "key authorization", "<token>.<fingerprint of its account key>": as
//     a file served on port 80 (http-01), as a DNS TXT record (dns-01), or
//     in a certificate on port 443 (tls-alpn-01). See challenges.go.
//  4. The client says "ready". The server looks. If the answer is right,
//     the authorization is valid.
//  5. When all authorizations of the order are valid, the client sends a
//     CSR (finalize), the CA signs it, and the client downloads the
//     certificate.
//
// The files of this package:
//
//	acme.go      the Server and its routes
//	jws.go       reads and checks the signed requests
//	handlers.go  one function for each step above
//	challenges.go  which challenges are offered, and running them (step 4)
//	http01.go, dns01.go, tlsalpn01.go  the three challenges
//	account.go   the account: see it, new key, close it
//	revoke.go    revocation by the client
//	limits.go    limits per address and per account
//	problem.go   the error answers
//
// Besides orders, a client can give its account a new key, close its
// account, and revoke its certificates (account.go, revoke.go).
//
// What is not here: External Account Binding and changing contacts.
package acme

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/metrics"
	"github.com/bastionxp/bastionxp-ca/internal/policy"
	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// PathPrefix is where the ACME endpoints live. DirectoryPath is the one
// address an ACME client is configured with; it finds the others there.
const (
	PathPrefix    = "/acme/"
	DirectoryPath = "/acme/directory"
)

const (
	// orderLifetime is how long a client has to complete an order.
	orderLifetime = 24 * time.Hour
	// nonceLifetime is how long an unused nonce is remembered.
	nonceLifetime = time.Hour
	// maxNonces limits the memory used for unused nonces.
	maxNonces = 10000
	// maxNamesPerOrder limits the size of one certificate.
	maxNamesPerOrder = 100
)

// Options are what a Server needs. All fields are required, except where
// noted.
type Options struct {
	CA    *ca.CA
	Store *store.Store
	Rules *policy.ACME
	Log   *slog.Logger

	// PublicURL is the address clients use to reach the CA, such as
	// "https://ca.example.com:8443". Optional: if empty, it is taken
	// from each request ("https://" and the Host header).
	PublicURL string

	// Dial opens the connection for a challenge request. Optional, and
	// only for tests: they use it to reach a test server instead of
	// port 80 of a real host.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// DNSResolver is the DNS server dns-01 asks, e.g. "10.0.0.53:53".
	// Optional: empty means the resolvers of this machine.
	DNSResolver string
	// LookupTXT looks up TXT records for dns-01. Optional, and only for
	// tests.
	LookupTXT func(ctx context.Context, name string) ([]string, error)
	// Metrics counts the certificates issued. Optional.
	Metrics *metrics.CA
	// Limits per source; see limits.go. Nil means DefaultLimits.
	Limits *Limits
	// Challenges are the challenge types offered, e.g. ["dns-01"].
	// Empty means all of ChallengeTypes.
	Challenges []string
	// Profile is the profile of the certificates: tls-server or one
	// based on it (acme.x509.cert_profile). Optional: tls-server.
	Profile *ca.X509Template
}

// Server is the ACME server. Create one with New and serve Handler under
// PathPrefix. It is safe for concurrent use.
type Server struct {
	// profile is the profile of every certificate it issues.
	profile ca.X509Template
	ca      *ca.CA
	store   *store.Store
	// rules can be replaced while the server runs; see SetRules.
	rules     atomic.Pointer[policy.ACME]
	log       *slog.Logger
	publicURL string

	// dial opens the connection for a challenge request.
	dial func(ctx context.Context, network, address string) (net.Conn, error)

	metrics *metrics.CA

	// lookupTXT looks up TXT records, for dns-01.
	lookupTXT func(ctx context.Context, name string) ([]string, error)

	// challenges are the types the administrator allows; see SetChallenges.
	challenges atomic.Pointer[[]string]

	// Limits; see limits.go.
	accountsPerIP    *windowLimiter
	ordersPerAccount *windowLimiter

	// nonces are the values handed out and not used yet. See newNonce.
	mu     sync.Mutex
	nonces map[string]time.Time // nonce -> when it expires
}

// New returns an ACME server.
func New(opts Options) *Server {
	dial := opts.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	lookupTXT := opts.LookupTXT
	if lookupTXT == nil {
		resolver := net.DefaultResolver
		if opts.DNSResolver != "" {
			resolver = directResolver(opts.DNSResolver)
		}
		lookupTXT = resolver.LookupTXT
	}
	limits := DefaultLimits
	if opts.Limits != nil {
		limits = *opts.Limits
	}
	profile := ca.TLSServer
	if opts.Profile != nil {
		profile = *opts.Profile
	}
	srv := &Server{
		profile:          profile,
		lookupTXT:        lookupTXT,
		accountsPerIP:    newWindowLimiter(limits.AccountsPerIP),
		ordersPerAccount: newWindowLimiter(limits.OrdersPerAccount),
		ca:               opts.CA,
		store:            opts.Store,
		log:              opts.Log,
		publicURL:        strings.TrimRight(opts.PublicURL, "/"),
		dial:             dial,
		metrics:          opts.Metrics,
		nonces:           make(map[string]time.Time),
	}
	srv.rules.Store(opts.Rules)
	srv.SetChallenges(opts.Challenges)
	return srv
}

// SetRules replaces the domains ACME clients may get certificates for.
// Requests that are being answered finish with the old rules.
func (s *Server) SetRules(rules *policy.ACME) {
	s.rules.Store(rules)
}

// Handler returns the HTTP handler with all ACME routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+DirectoryPath, s.handleDirectory)
	mux.HandleFunc("HEAD /acme/new-nonce", s.handleNewNonce)
	mux.HandleFunc("GET /acme/new-nonce", s.handleNewNonce)

	// Everything else is a signed POST. signed() checks the signature
	// and hands the handler the account and the request's content.
	mux.HandleFunc("POST /acme/new-account", s.handleNewAccount)
	mux.HandleFunc("POST /acme/acct/{id}", s.signed(s.handleAccount))
	mux.HandleFunc("POST /acme/new-order", s.signed(s.handleNewOrder))
	mux.HandleFunc("POST /acme/order/{id}", s.signed(s.handleOrder))
	mux.HandleFunc("POST /acme/order/{id}/finalize", s.signed(s.handleFinalize))
	mux.HandleFunc("POST /acme/authz/{id}", s.signed(s.handleAuthz))
	mux.HandleFunc("POST /acme/chall/{id}/{type}", s.signed(s.handleChallenge))
	mux.HandleFunc("POST /acme/cert/{id}", s.signed(s.handleCertificate))
	mux.HandleFunc("POST /acme/key-change", s.signed(s.handleKeyChange))
	mux.HandleFunc("POST /acme/revoke-cert", s.handleRevokeCert)
	mux.HandleFunc("GET "+RenewalInfoPath+"/{id}", s.handleRenewalInfo)
	return mux
}

// baseURL returns the address of the CA as the client sees it, without a
// path. All addresses the server hands out start with it.
func (s *Server) baseURL(r *http.Request) string {
	if s.publicURL != "" {
		return s.publicURL
	}
	return "https://" + r.Host
}

// The addresses of the things a client deals with.
func (s *Server) accountURL(r *http.Request, id string) string {
	return s.baseURL(r) + "/acme/acct/" + id
}
func (s *Server) orderURL(r *http.Request, id string) string {
	return s.baseURL(r) + "/acme/order/" + id
}
func (s *Server) authzURL(r *http.Request, id string) string {
	return s.baseURL(r) + "/acme/authz/" + id
}
func (s *Server) challengeURL(r *http.Request, authzID, challenge string) string {
	// A challenge is its authorization and its type.
	return s.baseURL(r) + "/acme/chall/" + authzID + "/" + challenge
}
func (s *Server) certificateURL(r *http.Request, orderID string) string {
	return s.baseURL(r) + "/acme/cert/" + orderID
}

// newNonce returns a fresh nonce and remembers it.
//
// A nonce is a random value the server hands out with every answer. The
// client must put one into its next request, and each works only once.
// This stops a recorded request from being sent a second time.
//
// Nonces are kept in memory. After a restart the old ones are unknown;
// a client then gets a "bad nonce" error with a new nonce, and tries
// again by itself.
func (s *Server) newNonce() (string, error) {
	nonce, err := randomID()
	if err != nil {
		return "", err
	}
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.nonces) >= maxNonces {
		for old, expires := range s.nonces {
			if now.After(expires) {
				delete(s.nonces, old)
			}
		}
		// Still full: someone is collecting nonces without using
		// them. Start over. Honest clients retry with a new nonce.
		if len(s.nonces) >= maxNonces {
			clear(s.nonces)
		}
	}
	s.nonces[nonce] = now.Add(nonceLifetime)
	return nonce, nil
}

// useNonce reports whether the nonce was handed out by this server and
// not used before. Afterwards it is used.
func (s *Server) useNonce(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expires, known := s.nonces[nonce]
	delete(s.nonces, nonce)
	return known && time.Now().Before(expires)
}

// randomID returns 128 random bits in a form that is safe in an address.
// It is used for nonces, tokens and the IDs of accounts and orders.
func randomID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}
