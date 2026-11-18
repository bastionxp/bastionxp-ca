// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func newTestVerifier(t *testing.T) *Verifier {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return New(key)
}

// A token issued for a profile, names and lifetime verifies back to exactly
// that profile, those names, the expiry it was given, and an ID.
func TestIssueAndVerify(t *testing.T) {
	v := newTestVerifier(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	v.now = func() time.Time { return now }

	names := []string{"web.example.com", "10.0.0.5"}
	tok, err := v.Issue(Options{Template: "tls-server", Names: names, ValidFor: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	grant, err := v.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Template != "tls-server" {
		t.Errorf("template = %q, want tls-server", grant.Template)
	}
	if !reflect.DeepEqual(grant.Names, names) {
		t.Errorf("names = %v, want %v", grant.Names, names)
	}
	if want := now.Add(5 * time.Minute); !grant.Expires.Equal(want) {
		t.Errorf("expires = %s, want %s", grant.Expires, want)
	}
	if grant.ID == "" {
		t.Error("token has no ID")
	}
}

// A token issued without a lifetime expires after DefaultValidity.
func TestIssueUsesDefaultValidity(t *testing.T) {
	v := newTestVerifier(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	v.now = func() time.Time { return now }

	tok, err := v.Issue(Options{Template: "tls-server", Names: []string{"a.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := v.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(DefaultValidity); !grant.Expires.Equal(want) {
		t.Errorf("expires = %s, want %s", grant.Expires, want)
	}
}

// The token's subject is the one given, or else the first name.
func TestSubject(t *testing.T) {
	v := newTestVerifier(t)
	names := []string{"deploy", "root"}

	tests := []struct {
		name    string
		subject string
		want    string
	}{
		{"given", "alice@example.com", "alice@example.com"},
		{"not given: the first name", "", "deploy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, err := v.Issue(Options{Subject: tt.subject, Template: "ssh-user", Names: names})
			if err != nil {
				t.Fatal(err)
			}
			grant, err := v.Verify(tok)
			if err != nil {
				t.Fatal(err)
			}
			if grant.Subject != tt.want {
				t.Errorf("subject = %q, want %q", grant.Subject, tt.want)
			}
		})
	}
}

// Two tokens issued for the same thing have different IDs, so each can be
// used only once.
func TestEveryTokenHasItsOwnID(t *testing.T) {
	v := newTestVerifier(t)
	var ids []string
	for range 2 {
		tok, err := v.Issue(Options{Template: "tls-server", Names: []string{"a.example.com"}})
		if err != nil {
			t.Fatal(err)
		}
		grant, err := v.Verify(tok)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, grant.ID)
	}
	if ids[0] == ids[1] {
		t.Errorf("two tokens share the ID %s", ids[0])
	}
}

// Issuing refuses a missing profile, missing or empty names, a lifetime that
// is negative or above the maximum, and a subject with spaces, line breaks
// or too many characters.
func TestIssueRejectsBadInput(t *testing.T) {
	v := newTestVerifier(t)
	tests := []struct {
		name     string
		subject  string
		template string
		names    []string
		validFor time.Duration
		wantErr  string
	}{
		{"no template", "", "", []string{"a"}, 0, "profile is required"},
		{"no names", "", "tls-server", nil, 0, "at least one name"},
		{"empty name", "", "tls-server", []string{"a", ""}, 0, "empty name"},
		{"negative validity", "", "tls-server", []string{"a"}, -time.Minute, "must be positive"},
		{"validity too long", "", "tls-server", []string{"a"}, MaxValidity + time.Second, "above the maximum"},
		{"subject with a space", "alice smith", "tls-server", []string{"a"}, 0, "must not contain spaces"},
		{"subject with a line break", "alice\nroot", "tls-server", []string{"a"}, 0, "must not contain spaces"},
		{"subject too long", strings.Repeat("a", maxSubjectLength+1), "tls-server", []string{"a"}, 0, "longer than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.Issue(Options{Subject: tt.subject, Template: tt.template, Names: tt.names, ValidFor: tt.validFor})
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// A token is accepted until it expires and refused from the second after.
func TestVerifyRejectsExpiredToken(t *testing.T) {
	v := newTestVerifier(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	v.now = func() time.Time { return now }

	tok, err := v.Issue(Options{Template: "tls-server", Names: []string{"a.example.com"}, ValidFor: time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	// Still valid one second before the end.
	v.now = func() time.Time { return now.Add(59 * time.Second) }
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("token rejected before it expired: %v", err)
	}

	v.now = func() time.Time { return now.Add(61 * time.Second) }
	if _, err := v.Verify(tok); !errors.Is(err, ErrInvalid) {
		t.Errorf("expired token: error = %v, want ErrInvalid", err)
	}
}

// A token signed with another CA's token key is refused.
func TestVerifyRejectsTokenFromAnotherKey(t *testing.T) {
	ours := newTestVerifier(t)
	theirs := newTestVerifier(t)

	tok, err := theirs.Issue(Options{Template: "tls-server", Names: []string{"a.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ours.Verify(tok); !errors.Is(err, ErrInvalid) {
		t.Errorf("error = %v, want ErrInvalid", err)
	}
}

// Damaged and forged tokens are refused: empty, not a token, without a
// signature, truncated, with trailing data, unsigned (alg none), and a
// payload swapped in from another token.
func TestVerifyRejectsDamagedTokens(t *testing.T) {
	v := newTestVerifier(t)
	tok, err := v.Issue(Options{Template: "tls-server", Names: []string{"a.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")

	// The same token with the payload replaced by one that asks for more.
	otherTok, err := v.Issue(Options{Template: "tls-server", Names: []string{"evil.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	swapped := parts[0] + "." + strings.Split(otherTok, ".")[1] + "." + parts[2]

	tests := map[string]string{
		"empty":            "",
		"not a token":      "hello",
		"no signature":     parts[0] + "." + parts[1] + ".",
		"swapped payload":  swapped,
		"truncated":        tok[:len(tok)-4],
		"unsigned (none)":  "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + parts[1] + ".",
		"trailing garbage": tok + ".extra",
	}
	for name, bad := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(bad); !errors.Is(err, ErrInvalid) {
				t.Errorf("error = %v, want ErrInvalid", err)
			}
		})
	}
}

// signClaims builds a correctly signed token with claims of the test's
// choosing, to check that Verify does not rely on Issue being the only
// thing that ever signs with the key.
func signClaims(t *testing.T, v *Verifier, claims ...any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: v.key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	builder := jwt.Signed(signer)
	for _, c := range claims {
		builder = builder.Claims(c)
	}
	tok, err := builder.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// A token missing any required claim (expiry, ID, issuer, subject, audience,
// profile, names), or meant for logins, is refused, while the same token
// complete is accepted.
func TestVerifyRejectsIncompleteTokens(t *testing.T) {
	v := newTestVerifier(t)
	expiry := jwt.NewNumericDate(time.Now().Add(time.Minute))
	grant := grantClaims{Template: "tls-server", Names: []string{"a.example.com"}}
	aud := jwt.Audience{audienceCertificate}

	tests := map[string]string{
		"no expiry":    signClaims(t, v, jwt.Claims{Issuer: issuer, Audience: aud, Subject: "a", ID: "1"}, grant),
		"no ID":        signClaims(t, v, jwt.Claims{Issuer: issuer, Audience: aud, Subject: "a", Expiry: expiry}, grant),
		"wrong issuer": signClaims(t, v, jwt.Claims{Issuer: "someone-else", Audience: aud, Subject: "a", ID: "1", Expiry: expiry}, grant),
		"no subject":   signClaims(t, v, jwt.Claims{Issuer: issuer, Audience: aud, ID: "1", Expiry: expiry}, grant),
		"bad subject":  signClaims(t, v, jwt.Claims{Issuer: issuer, Audience: aud, Subject: "a\nb", ID: "1", Expiry: expiry}, grant),
		"complete":     signClaims(t, v, jwt.Claims{Issuer: issuer, Audience: aud, Subject: "a", ID: "1", Expiry: expiry}, grant),
		"no audience":  signClaims(t, v, jwt.Claims{Issuer: issuer, Subject: "a", ID: "1", Expiry: expiry}, grant),
		"for logins":   signClaims(t, v, jwt.Claims{Issuer: issuer, Audience: jwt.Audience{audienceLogin}, Subject: "a", ID: "1", Expiry: expiry}, grant),
		"no template":  signClaims(t, v, jwt.Claims{Issuer: issuer, Audience: aud, Subject: "a", ID: "1", Expiry: expiry}, grantClaims{Names: grant.Names}),
		"no names":     signClaims(t, v, jwt.Claims{Issuer: issuer, Audience: aud, Subject: "a", ID: "1", Expiry: expiry}, grantClaims{Template: "tls-server"}),
	}
	for name, tok := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(tok)
			// The complete token shows that the others fail for the
			// field they lack, and not for a mistake in this test.
			if name == "complete" {
				if err != nil {
					t.Errorf("complete token rejected: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("error = %v, want ErrInvalid", err)
			}
		})
	}
}

// The token key is created once, with mode 600, and loaded unchanged
// afterwards, so tokens keep working after a restart.
func TestLoadOrCreateKey(t *testing.T) {
	dir := t.TempDir()

	created, err := LoadOrCreateKey(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 600", perm)
	}

	// A second call must return the same key, not make a new one:
	// otherwise tokens would stop working after a restart.
	loaded, err := LoadOrCreateKey(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !created.Equal(loaded) {
		t.Error("the second call returned a different key")
	}
}

// A damaged token key file is refused, not replaced.
func TestLoadOrCreateKeyRejectsBadFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, KeyFile), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(dir, nil); err == nil {
		t.Fatal("expected an error for a damaged key file, got nil")
	}
}

// Ten callers creating the token key at the same moment all get the same
// key, and no temporary files are left behind.
func TestLoadOrCreateKeyFromManyProgramsAtOnce(t *testing.T) {
	dir := t.TempDir()

	const programs = 10
	keys := make([]*ecdsa.PrivateKey, programs)
	errs := make([]error, programs)
	var wg sync.WaitGroup
	for i := range programs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys[i], errs[i] = LoadOrCreateKey(dir, nil)
		}()
	}
	wg.Wait()

	for i := range programs {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if !keys[i].Equal(keys[0]) {
			t.Fatalf("caller %d got a different key than caller 0", i)
		}
	}

	// No temporary files may be left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != KeyFile {
		t.Errorf("directory has %d files, want only %s", len(entries), KeyFile)
	}
}

// A token records who created it, separately from who it is for (the
// subject).
func TestCreatedBy(t *testing.T) {
	v := newTestVerifier(t)

	tok, err := v.Issue(Options{Template: "ssh-host", Names: []string{"web1"}, CreatedBy: "ganesh"})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := v.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if grant.CreatedBy != "ganesh" {
		t.Errorf("created by = %q, want ganesh", grant.CreatedBy)
	}
	// Who created a token and who it is for are two different things.
	if grant.Subject != "web1" {
		t.Errorf("subject = %q, want web1", grant.Subject)
	}
}

// A token can be tied to a public key's fingerprint, and a token without one
// is tied to no key.
func TestKeyFingerprint(t *testing.T) {
	v := newTestVerifier(t)

	tok, err := v.Issue(Options{Template: "ssh-user", Names: []string{"alice"}, KeyFingerprint: "SHA256:abc"})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := v.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if grant.KeyFingerprint != "SHA256:abc" {
		t.Errorf("key fingerprint = %q, want SHA256:abc", grant.KeyFingerprint)
	}

	// Without one the token is not tied to a key.
	tok, err = v.Issue(Options{Template: "ssh-user", Names: []string{"alice"}})
	if err != nil {
		t.Fatal(err)
	}
	grant, err = v.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if grant.KeyFingerprint != "" {
		t.Errorf("key fingerprint = %q, want none", grant.KeyFingerprint)
	}
}
