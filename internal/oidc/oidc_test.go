// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/bastionxp/bastionxp-ca/internal/oidc"
	"github.com/bastionxp/bastionxp-ca/internal/oidc/oidctest"
)

const redirectURI = "https://ca.example.com:8443/v1/oidc/callback"

func newTestClient(t *testing.T) (*oidc.Client, *oidctest.Fake) {
	t.Helper()
	fake := oidctest.NewFake("bastionxp-ca", "the-secret")
	t.Cleanup(fake.Close)
	return oidc.New(oidc.Config{
		Issuer: fake.Issuer(), ClientID: "bastionxp-ca", ClientSecret: "the-secret",
		UsernameClaim: "preferred_username", GroupsClaim: "groups",
		Scopes: []string{"openid", "profile", "email"},
	}), fake
}

// visit plays the browser and returns what the provider sends back.
func visit(t *testing.T, client *oidc.Client, nonce, verifier string) url.Values {
	t.Helper()
	address, err := client.AuthorizeURL(context.Background(), redirectURI, "my-state", nonce, verifier)
	if err != nil {
		t.Fatal(err)
	}
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noFollow.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("the provider answered %s, want a redirect", resp.Status)
	}
	back, _ := url.Parse(resp.Header.Get("Location"))
	return back.Query()
}

// An OIDC login returns the state, the username in lower case and the
// groups; a code works only once.
func TestLogin(t *testing.T) {
	client, fake := newTestClient(t)
	fake.SignInAs("Alice@Corp.Example.com", "linux-users", "dba")
	verifier := oauth2.GenerateVerifier()

	back := visit(t, client, "nonce-1", verifier)
	if back.Get("state") != "my-state" {
		t.Errorf("state = %q", back.Get("state"))
	}
	id, err := client.Login(context.Background(), back.Get("code"), redirectURI, "nonce-1", verifier)
	if err != nil {
		t.Fatal(err)
	}
	// Lower case, to match Linux and SSSD login names.
	if id.Username != "alice@corp.example.com" || id.Source != "oidc" {
		t.Errorf("identity = %+v", id)
	}
	if !reflect.DeepEqual(id.Groups, []string{"linux-users", "dba"}) {
		t.Errorf("groups = %v", id.Groups)
	}

	// A code works once.
	if _, err := client.Login(context.Background(), back.Get("code"), redirectURI, "nonce-1", verifier); !errors.Is(err, oidc.ErrLoginFailed) {
		t.Errorf("second use of the code: error = %v, want ErrLoginFailed", err)
	}
}

// The provider must hand out a code only to the one who knows the PKCE
// verifier: a code that leaks from the browser is of no use.
func TestLoginNeedsTheRightVerifier(t *testing.T) {
	client, fake := newTestClient(t)
	fake.SignInAs("alice@corp.example.com")
	back := visit(t, client, "n", oauth2.GenerateVerifier())

	_, err := client.Login(context.Background(), back.Get("code"), redirectURI, "n", oauth2.GenerateVerifier())
	if !errors.Is(err, oidc.ErrLoginFailed) {
		t.Errorf("error = %v, want ErrLoginFailed", err)
	}
}

// An ID token signed with an unknown key, for another application, from
// another issuer, expired, for another login's nonce, or with too many
// groups fails the login, with no identity.
func TestLoginRefusesBadIDTokens(t *testing.T) {
	for name, tamper := range map[string]oidctest.Tamper{
		"signed with an unknown key": oidctest.OtherKey,
		"for another application":    oidctest.OtherAudience,
		"from another issuer":        oidctest.OtherIssuer,
		"expired":                    oidctest.Expired,
		"for another login (nonce)":  oidctest.OtherNonce,
		"too many groups":            oidctest.GroupsOverflow,
	} {
		t.Run(name, func(t *testing.T) {
			client, fake := newTestClient(t)
			fake.SignInAs("alice@corp.example.com", "linux-users")
			fake.Misbehave(tamper)
			verifier := oauth2.GenerateVerifier()
			back := visit(t, client, "n", verifier)

			id, err := client.Login(context.Background(), back.Get("code"), redirectURI, "n", verifier)
			if !errors.Is(err, oidc.ErrLoginFailed) {
				t.Errorf("error = %v, want ErrLoginFailed", err)
			}
			if id.Username != "" {
				t.Errorf("an identity was returned with the error: %+v", id)
			}
		})
	}
}

// A provider answer without an ID token fails the login, with no identity.
func TestLoginWithoutIDToken(t *testing.T) {
	client, fake := newTestClient(t)
	fake.SignInAs("alice@corp.example.com")
	fake.Misbehave(oidctest.NoIDToken)
	verifier := oauth2.GenerateVerifier()
	back := visit(t, client, "n", verifier)

	if id, err := client.Login(context.Background(), back.Get("code"), redirectURI, "n", verifier); err == nil || id.Username != "" {
		t.Errorf("identity %+v, error %v; want an error and no identity", id, err)
	}
}

// The username and groups claims: no groups claim, one group as a string; a
// missing or empty name, or groups that are not a list, are errors.
func TestClaims(t *testing.T) {
	tests := []struct {
		name       string
		claims     map[string]any
		wantUser   string
		wantGroups []string
		wantErr    string
	}{
		{"no groups claim", map[string]any{"preferred_username": "a@x"}, "a@x", nil, ""},
		{"one group as a string", map[string]any{"preferred_username": "a@x", "groups": "ops"}, "a@x", []string{"ops"}, ""},
		{"no name", map[string]any{"email": "a@x"}, "", nil, "preferred_username"},
		{"empty name", map[string]any{"preferred_username": "  "}, "", nil, "preferred_username"},
		{"groups not a list", map[string]any{"preferred_username": "a@x", "groups": 42}, "", nil, "not a list"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, fake := newTestClient(t)
			fake.SetClaims(tt.claims)
			verifier := oauth2.GenerateVerifier()
			back := visit(t, client, "n", verifier)
			id, err := client.Login(context.Background(), back.Get("code"), redirectURI, "n", verifier)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if id.Username != tt.wantUser || !reflect.DeepEqual(id.Groups, tt.wantGroups) {
				t.Errorf("identity = %+v", id)
			}
		})
	}
}

// A wrong client secret is reported as a configuration error, not a failed
// login, and the error does not contain the secret.
func TestWrongClientSecret(t *testing.T) {
	fake := oidctest.NewFake("bastionxp-ca", "the-right-secret")
	defer fake.Close()
	fake.SignInAs("alice@corp.example.com")
	client := oidc.New(oidc.Config{Issuer: fake.Issuer(), ClientID: "bastionxp-ca", ClientSecret: "wrong", UsernameClaim: "preferred_username"})
	verifier := oauth2.GenerateVerifier()
	back := visit(t, client, "n", verifier)

	_, err := client.Login(context.Background(), back.Get("code"), redirectURI, "n", verifier)
	// A configuration mistake: an error, but not "try again".
	if err == nil || errors.Is(err, oidc.ErrLoginFailed) {
		t.Errorf("error = %v, want a plain error", err)
	}
	if strings.Contains(err.Error(), "wrong") && strings.Contains(err.Error(), "secret=wrong") {
		t.Errorf("the error contains the client secret: %v", err)
	}
}

// A provider that is down when the CA starts must not stop the CA; the
// logins fail until it is back.
func TestProviderUnreachable(t *testing.T) {
	client := oidc.New(oidc.Config{Issuer: "http://127.0.0.1:1", ClientID: "bastionxp-ca", UsernameClaim: "preferred_username"})
	if _, err := client.AuthorizeURL(context.Background(), redirectURI, "s", "n", "v"); err == nil || !strings.Contains(err.Error(), "cannot reach") {
		t.Errorf("error = %v, want one that says the provider cannot be reached", err)
	}
}

// With the email address as the name, the provider must say it checked
// the address. Otherwise anyone could log in with a chosen address.
func TestEmailMustBeVerified(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		ok     bool
	}{
		{"verified", map[string]any{"email": "alice@gmail.com", "email_verified": true}, true},
		{"verified, as text", map[string]any{"email": "alice@gmail.com", "email_verified": "true"}, true},
		{"not verified", map[string]any{"email": "alice@corp.example.com", "email_verified": false}, false},
		{"no word on it", map[string]any{"email": "alice@corp.example.com"}, false},
		{"something else", map[string]any{"email": "alice@corp.example.com", "email_verified": "yes"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := oidctest.NewFake("bastionxp-ca", "the-secret")
			defer fake.Close()
			fake.SetClaims(tt.claims)
			client := oidc.New(oidc.Config{Issuer: fake.Issuer(), ClientID: "bastionxp-ca", ClientSecret: "the-secret", UsernameClaim: "email"})
			verifier := oauth2.GenerateVerifier()
			back := visit(t, client, "n", verifier)

			id, err := client.Login(context.Background(), back.Get("code"), redirectURI, "n", verifier)
			if tt.ok && (err != nil || id.Username == "") {
				t.Errorf("identity %+v, error %v; want a login", id, err)
			}
			if !tt.ok && (!errors.Is(err, oidc.ErrLoginFailed) || id.Username != "") {
				t.Errorf("identity %+v, error %v; want a refusal", id, err)
			}
		})
	}
}

// The check is for the email claim only. A claim the provider controls,
// such as preferred_username, needs no email_verified.
func TestPreferredUsernameNeedsNoEmailVerified(t *testing.T) {
	client, fake := newTestClient(t)
	fake.SetClaims(map[string]any{"preferred_username": "alice@corp.example.com", "email": "x@y", "email_verified": false})
	verifier := oauth2.GenerateVerifier()
	back := visit(t, client, "n", verifier)
	if id, err := client.Login(context.Background(), back.Get("code"), redirectURI, "n", verifier); err != nil || id.Username != "alice@corp.example.com" {
		t.Errorf("identity %+v, error %v", id, err)
	}
}
