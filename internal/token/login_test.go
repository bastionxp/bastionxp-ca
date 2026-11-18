// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
)

func testLogin() Login {
	return Login{
		ID:             "login-1",
		Provider:       "oidc",
		Callback:       "http://127.0.0.1:51234/callback",
		ClientState:    "random-value",
		Template:       "ssh-user",
		Names:          []string{"alice", "deploy"},
		Subject:        "alice",
		ValidFor:       time.Hour,
		KeyFingerprint: "SHA256:abc",
	}
}

// A signed login state verifies back to exactly the login it was made from.
func TestIssueAndVerifyLogin(t *testing.T) {
	v := newTestVerifier(t)
	want := testLogin()

	signed, err := v.IssueLogin(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.VerifyLogin(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("got %+v, want %+v", *got, want)
	}
}

// A login state without a callback, client state, profile or provider is
// refused.
func TestIssueLoginNeedsTheBasics(t *testing.T) {
	v := newTestVerifier(t)
	tests := map[string]func(*Login){
		"no callback":     func(l *Login) { l.Callback = "" },
		"no client state": func(l *Login) { l.ClientState = "" },
		"no template":     func(l *Login) { l.Template = "" },
		"no provider":     func(l *Login) { l.Provider = "" },
	}
	for name, remove := range tests {
		t.Run(name, func(t *testing.T) {
			login := testLogin()
			remove(&login)
			if _, err := v.IssueLogin(login); err == nil {
				t.Error("expected an error, got nil")
			}
		})
	}
}

// A login state is accepted until LoginValidity ends and refused after.
func TestVerifyLoginRejectsExpiredLogin(t *testing.T) {
	v := newTestVerifier(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	v.now = func() time.Time { return now }
	signed, err := v.IssueLogin(testLogin())
	if err != nil {
		t.Fatal(err)
	}

	v.now = func() time.Time { return now.Add(LoginValidity - time.Second) }
	if _, err := v.VerifyLogin(signed); err != nil {
		t.Fatalf("login rejected before it expired: %v", err)
	}
	v.now = func() time.Time { return now.Add(LoginValidity + time.Second) }
	if _, err := v.VerifyLogin(signed); !errors.Is(err, ErrInvalid) {
		t.Errorf("expired login: error = %v, want ErrInvalid", err)
	}
}

// The callback in a login is where a token will be sent. Nobody but the
// CA may be able to write one.
func TestVerifyLoginRejectsLoginsNotSignedByThisCA(t *testing.T) {
	ours := newTestVerifier(t)
	theirs := newTestVerifier(t)

	forged, err := theirs.IssueLogin(Login{Callback: "https://attacker.example/", ClientState: "x", Template: "ssh-user", Provider: "oidc"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ours.VerifyLogin(forged); !errors.Is(err, ErrInvalid) {
		t.Errorf("login signed by another key: error = %v, want ErrInvalid", err)
	}

	for _, bad := range []string{"", "hello", forged + "x"} {
		if _, err := ours.VerifyLogin(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("VerifyLogin(%q): error = %v, want ErrInvalid", bad, err)
		}
	}
}

// Logins and one-time tokens are signed with the same key. Neither may be
// accepted in place of the other.
func TestLoginsAndOneTimeTokensAreNotInterchangeable(t *testing.T) {
	v := newTestVerifier(t)

	signed, err := v.IssueLogin(testLogin())
	if err != nil {
		t.Fatal(err)
	}
	// A login names a template and names, like a token. It must still
	// not work as one: it was made before anybody logged in.
	if _, err := v.Verify(signed); !errors.Is(err, ErrInvalid) {
		t.Errorf("login used as a one-time token: error = %v, want ErrInvalid", err)
	}

	oneTime, err := v.Issue(Options{Template: "ssh-user", Names: []string{"alice"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyLogin(oneTime); !errors.Is(err, ErrInvalid) {
		t.Errorf("one-time token used as a login: error = %v, want ErrInvalid", err)
	}
}

// A login state without an expiry, audience or callback is refused, while
// the same claims complete are accepted.
func TestVerifyLoginRejectsIncompleteLogins(t *testing.T) {
	v := newTestVerifier(t)
	expiry := jwt.NewNumericDate(time.Now().Add(time.Minute))
	aud := jwt.Audience{audienceLogin}
	complete := testLogin()
	noCallback := testLogin()
	noCallback.Callback = ""

	tests := map[string]string{
		"no expiry":   signClaims(t, v, jwt.Claims{Issuer: issuer, Audience: aud}, complete),
		"no audience": signClaims(t, v, jwt.Claims{Issuer: issuer, Expiry: expiry}, complete),
		"no callback": signClaims(t, v, jwt.Claims{Issuer: issuer, Audience: aud, Expiry: expiry}, noCallback),
	}
	for name, signed := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := v.VerifyLogin(signed); !errors.Is(err, ErrInvalid) {
				t.Errorf("error = %v, want ErrInvalid", err)
			}
		})
	}

	// The same claims, complete, are accepted.
	ok := signClaims(t, v, jwt.Claims{Issuer: issuer, Audience: aud, Expiry: expiry}, complete)
	if _, err := v.VerifyLogin(ok); err != nil {
		t.Errorf("complete login rejected: %v", err)
	}
}

// Each login gets its own ID, even when none is given.
func TestIssueLoginGivesEachLoginAnID(t *testing.T) {
	v := newTestVerifier(t)
	login := testLogin()
	login.ID = ""
	first, _ := v.IssueLogin(login)
	second, _ := v.IssueLogin(login)
	a, err := v.VerifyLogin(first)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := v.VerifyLogin(second)
	if a.ID == "" || a.ID == b.ID {
		t.Errorf("IDs %q and %q, want two different ones", a.ID, b.ID)
	}
}

// Values derived for a login (the PKCE verifier, the nonce) are URL-safe,
// the same for the same input and key, different for another login, purpose
// or CA, and the same after a restart with the same key.
func TestDerive(t *testing.T) {
	v := newTestVerifier(t)
	a := v.Derive("pkce", "login-1")
	if len(a) != 43 || strings.ContainsAny(a, "+/=") {
		t.Errorf("derived = %q, want 43 URL-safe characters", a)
	}
	if a != v.Derive("pkce", "login-1") {
		t.Error("the same input gave two values")
	}
	for name, other := range map[string]string{
		"another login":   v.Derive("pkce", "login-2"),
		"another purpose": v.Derive("nonce", "login-1"),
		"another CA":      newTestVerifier(t).Derive("pkce", "login-1"),
		// The separator keeps purpose and ID apart.
		"shifted": v.Derive("pkcel", "ogin-1"),
	} {
		if other == a {
			t.Errorf("%s gave the same value", name)
		}
	}
	// The same key, loaded again, derives the same values: logins
	// survive a restart of the server.
	if again := New(v.key); again.Derive("pkce", "login-1") != a {
		t.Error("a new Verifier with the same key derives other values")
	}
}
