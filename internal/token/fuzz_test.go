// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

// FuzzVerify feeds arbitrary text to the token and login checks. They must
// never panic, and never accept anything this verifier did not sign: the
// fuzzer has no key, so whatever passes must be one of the seeds.
func FuzzVerify(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	v := New(key)
	valid, err := v.Issue(Options{Template: "tls-server", Names: []string{"web.example.com"}, ValidFor: time.Hour})
	if err != nil {
		f.Fatal(err)
	}
	login, err := v.IssueLogin(Login{Provider: "oidc", Callback: "http://127.0.0.1:1/cb", ClientState: "s", Template: "ssh-user"})
	if err != nil {
		f.Fatal(err)
	}
	seeds := map[string]bool{valid: true, login: true}
	f.Add(valid)
	f.Add(login)
	f.Add("")
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.")
	f.Fuzz(func(t *testing.T, text string) {
		if _, err := v.Verify(text); err == nil && !seeds[text] {
			t.Errorf("accepted a token it did not sign: %q", text)
		}
		if _, err := v.VerifyLogin(text); err == nil && !seeds[text] {
			t.Errorf("accepted a login it did not sign: %q", text)
		}
	})
}
