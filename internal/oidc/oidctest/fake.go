// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package oidctest has a stand-in for an OpenID Connect identity
// provider, for tests.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Fake is a stand-in for an identity provider. It
// has no login page: a test says beforehand who sits at the browser, and
// the fake answers at once.
//
// It can also misbehave, the way a broken or hostile provider would, so
// that tests can make sure the CA notices.
type Fake struct {
	ClientID     string
	ClientSecret string

	server *httptest.Server
	key    *rsa.PrivateKey
	other  *rsa.PrivateKey // signs tokens that must not pass

	mu     sync.Mutex
	user   map[string]any // the claims of who is at the browser; nil presses Cancel
	codes  map[string]pending
	count  int
	tamper Tamper
}

// pending is a code handed out and not yet exchanged.
type pending struct {
	claims      map[string]any
	nonce       string
	challenge   string
	redirectURI string
}

// Tamper makes the fake hand out a bad ID token, to test that the CA
// refuses it.
type Tamper int

const (
	Honest         Tamper = iota
	OtherKey              // signed with a key the provider does not publish
	OtherAudience         // made for another application
	OtherIssuer           // claims to be from another provider
	Expired               // expired an hour ago
	OtherNonce            // for another login
	NoIDToken             // the answer has no ID token at all
	GroupsOverflow        // Entra's "too many groups" form
)

// NewFake starts a fake provider. Close it at the end of the test.
func NewFake(clientID, clientSecret string) *Fake {
	f := &Fake{ClientID: clientID, ClientSecret: clientSecret, codes: make(map[string]pending)}
	var err error
	if f.key, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
	if f.other, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", f.handleDiscovery)
	mux.HandleFunc("GET /keys", f.handleKeys)
	mux.HandleFunc("GET /authorize", f.handleAuthorize)
	mux.HandleFunc("POST /token", f.handleToken)
	f.server = httptest.NewServer(mux)
	return f
}

// Close stops the fake.
func (f *Fake) Close() { f.server.Close() }

// Issuer is the fake's address, for the CA's configuration.
func (f *Fake) Issuer() string { return f.server.URL }

// SignInAs says who sits at the browser from now on: their name in the
// "preferred_username" claim and their groups in the "groups" claim. An
// empty username means a person who presses "Cancel".
func (f *Fake) SignInAs(username string, groups ...string) {
	if username == "" {
		f.SetClaims(nil)
		return
	}
	claims := map[string]any{"preferred_username": username, "email": username}
	if len(groups) > 0 {
		claims["groups"] = groups
	}
	f.SetClaims(claims)
}

// SetClaims sets exactly the claims of the person at the browser.
func (f *Fake) SetClaims(claims map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.user = claims
}

// Misbehave makes the fake hand out bad ID tokens from now on.
func (f *Fake) Misbehave(t Tamper) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tamper = t
}

func (f *Fake) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                f.server.URL,
		"authorization_endpoint":                f.server.URL + "/authorize",
		"token_endpoint":                        f.server.URL + "/token",
		"jwks_uri":                              f.server.URL + "/keys",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (f *Fake) handleKeys(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &f.key.PublicKey, KeyID: "key-1", Algorithm: "RS256", Use: "sig"},
	}})
}

// handleAuthorize is the login page. It sends the browser straight back.
func (f *Fake) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != f.ClientID || q.Get("response_type") != "code" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// The real providers insist on PKCE for this kind of client; the
	// fake does too, so a CA that forgets it fails the tests.
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "PKCE required", http.StatusBadRequest)
		return
	}
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || redirect.Host == "" {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	back := url.Values{"state": {q.Get("state")}}
	if f.user == nil {
		back.Set("error", "access_denied")
	} else {
		f.count++
		code := fmt.Sprintf("code-%d", f.count)
		f.codes[code] = pending{claims: f.user, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirectURI: q.Get("redirect_uri")}
		back.Set("code", code)
	}
	f.mu.Unlock()

	redirect.RawQuery = back.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (f *Fake) handleToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != f.ClientID || secret != f.ClientSecret {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	f.mu.Lock()
	code := r.PostForm.Get("code")
	p, found := f.codes[code]
	delete(f.codes, code) // a code works once
	tamper := f.tamper
	f.mu.Unlock()

	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	switch {
	case !found, r.PostForm.Get("redirect_uri") != p.redirectURI,
		base64.RawURLEncoding.EncodeToString(sum[:]) != p.challenge:
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	answer := map[string]any{"access_token": "access-token", "token_type": "Bearer", "expires_in": 3600}
	if tamper != NoIDToken {
		answer["id_token"] = f.idToken(p, tamper)
	}
	writeJSON(w, answer)
}

// idToken makes the ID token for a code, honest or not.
func (f *Fake) idToken(p pending, tamper Tamper) string {
	key, issuer, audience, nonce := f.key, f.server.URL, f.ClientID, p.nonce
	now := time.Now()
	switch tamper {
	case OtherKey:
		key = f.other
	case OtherAudience:
		audience = "some-other-app"
	case OtherIssuer:
		issuer = "https://evil.example.com"
	case Expired:
		now = now.Add(-2 * time.Hour)
	case OtherNonce:
		nonce = "a-nonce-of-another-login"
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "key-1"))
	if err != nil {
		panic(err)
	}
	claims := map[string]any{}
	for k, v := range p.claims {
		claims[k] = v
	}
	if tamper == GroupsOverflow {
		delete(claims, "groups")
		claims["_claim_names"] = map[string]any{"groups": "src1"}
		claims["_claim_sources"] = map[string]any{"src1": map[string]any{"endpoint": "https://graph.example.com/..."}}
	}
	token, err := jwt.Signed(signer).
		Claims(jwt.Claims{
			Issuer:   issuer,
			Subject:  "subject-of-" + fmt.Sprint(claims["preferred_username"]),
			Audience: jwt.Audience{audience},
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
		}).
		Claims(map[string]any{"nonce": nonce}).
		Claims(claims).
		Serialize()
	if err != nil {
		panic(err)
	}
	return token
}

func writeJSON(w http.ResponseWriter, value any) {
	writeJSONStatus(w, http.StatusOK, value)
}

// writeJSONStatus sends a JSON answer. The content type must be set
// before the status: OAuth clients read the error code only from JSON.
func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
