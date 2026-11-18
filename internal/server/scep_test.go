// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/scep"
	"github.com/bastionxp/bastionxp-ca/internal/store"
	"github.com/bastionxp/bastionxp-ca/internal/token"
)

// scepEnv is a CA with the SCEP server switched on, and a device talking
// to it. The challenge of a request is a real one-time token here.
type scepEnv struct {
	*testEnv
	device  *scep.Client
	caCerts *scep.CACerts
	url     string
}

func newSCEPEnv(t *testing.T) *scepEnv { return newSCEPEnvWith(t, nil) }

// newSCEPEnvWith is newSCEPEnv with a static challenge, if not nil.
func newSCEPEnvWith(t *testing.T, static *SCEPStatic) *scepEnv {
	t.Helper()
	dir := t.TempDir()
	if err := ca.Init(dir, ca.InitOptions{Name: "Test", Organization: "Test Org", KeyType: ca.KeyTypeECDSA}); err != nil {
		t.Fatal(err)
	}
	authority, err := ca.Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := token.LoadOrCreateKey(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(dir, store.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ra, err := scep.LoadOrCreateRA(dir, authority)
	if err != nil {
		t.Fatal(err)
	}

	tokens := token.New(key)
	handler := New(Options{
		CA: authority, Tokens: tokens, Store: db,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		SCEPRA:     ra,
		SCEPStatic: static,
	}).Handler()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	env := &scepEnv{
		testEnv: &testEnv{ca: authority, tokens: tokens, handler: handler},
		url:     ts.URL + scep.Path,
	}
	env.device = scep.NewClient(env.url, ts.Client())
	env.caCerts, err = env.device.GetCACerts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// enroll plays a device: a new key, a CSR for the names with the
// challenge, and the request.
func (e *scepEnv) enroll(t *testing.T, challenge string, names ...string) (*x509.Certificate, *rsa.PrivateKey, error) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := e.enrollKey(t, key, challenge, names...)
	return cert, key, err
}

func (e *scepEnv) enrollKey(t *testing.T, key *rsa.PrivateKey, challenge string, names ...string) (*x509.Certificate, error) {
	t.Helper()
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}
	csr, err := scep.NewCSR(template, key, challenge)
	if err != nil {
		t.Fatal(err)
	}
	return e.device.Enroll(context.Background(), csr, key, e.caCerts)
}

// The whole road: an administrator makes a token, the device sends it as
// its SCEP challenge and gets a certificate.
func TestSCEPEnrollWithToken(t *testing.T) {
	env := newSCEPEnv(t)
	tok := env.issueToken(t, "tls-client", "device1.example.com")

	cert, key, err := env.enroll(t, tok, "device1.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Error("the certificate is for another key")
	}
	// The token decided the kind of certificate.
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("extended key usage = %v, want client auth only", cert.ExtKeyUsage)
	}
	roots := x509.NewCertPool()
	roots.AddCert(env.ca.RootCert())
	intermediates := x509.NewCertPool()
	intermediates.AddCert(env.ca.IntermediateCert())
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Errorf("the certificate does not verify against the root: %v", err)
	}
	// SCEP cannot ask for a validity, so the template's default applies.
	if got := cert.NotAfter.Sub(cert.NotBefore).Round(time.Hour); got != ca.TLSClient.DefaultValidity {
		t.Errorf("validity = %s, want %s", got, ca.TLSClient.DefaultValidity)
	}

	// The token is spent: a second device cannot use it.
	if _, _, err := env.enroll(t, tok, "device1.example.com"); err == nil {
		t.Error("a second certificate was issued with the same token")
	}
}

// The rules for tokens hold for SCEP as they do for the API.
func TestSCEPEnrollIsHeldToTheToken(t *testing.T) {
	env := newSCEPEnv(t)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherFingerprint, err := ca.X509Fingerprint(otherKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	boundToOtherKey, err := env.tokens.Issue(token.Options{
		Template: "tls-client", Names: []string{"device1.example.com"}, KeyFingerprint: otherFingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherEnv := newTestEnv(t)
	fromOtherCA := otherEnv.issueToken(t, "tls-client", "device1.example.com")

	tests := []struct {
		name      string
		challenge string
		names     []string
	}{
		{"name not in the token", env.issueToken(t, "tls-client", "device1.example.com"), []string{"device2.example.com"}},
		{"an extra name", env.issueToken(t, "tls-client", "device1.example.com"), []string{"device1.example.com", "admin.example.com"}},
		{"token for an SSH certificate", env.issueToken(t, "ssh-user", "device1.example.com"), []string{"device1.example.com"}},
		{"token tied to another key", boundToOtherKey, []string{"device1.example.com"}},
		{"token of another CA", fromOtherCA, []string{"device1.example.com"}},
		{"a made-up challenge", "letmein", []string{"device1.example.com"}},
		{"a damaged token", env.issueToken(t, "tls-client", "device1.example.com") + "x", []string{"device1.example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, _, err := env.enroll(t, tt.challenge, tt.names...)
			if err == nil || !strings.Contains(err.Error(), "refused") {
				t.Errorf("error = %v, want a refusal", err)
			}
			if cert != nil {
				t.Error("a certificate was issued")
			}
		})
	}

	// A token tied to a key works for that key.
	cert, err := env.enrollKey(t, otherKey, boundToOtherKey, "device1.example.com")
	if err != nil || cert == nil {
		t.Errorf("the key the token was made for: %v", err)
	}
}

// A request refused for its names does not use up the token, as with the API.
func TestSCEPRefusalDoesNotSpendTheToken(t *testing.T) {
	env := newSCEPEnv(t)
	tok := env.issueToken(t, "tls-client", "device1.example.com")

	if _, _, err := env.enroll(t, tok, "device2.example.com"); err == nil {
		t.Fatal("a certificate was issued for a name that is not in the token")
	}
	if _, _, err := env.enroll(t, tok, "device1.example.com"); err != nil {
		t.Errorf("the corrected request: %v", err)
	}
}

// A device's key must be strong enough, as for every other certificate.
func TestSCEPRefusesWeakKeys(t *testing.T) {
	env := newSCEPEnv(t)
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tok := env.issueToken(t, "tls-client", "device1.example.com")
	if _, err := env.enrollKey(t, weak, tok, "device1.example.com"); err == nil {
		t.Error("a certificate was issued for a 1024 bit key")
	}
}

// The SCEP endpoint is not found unless SCEP is configured.
func TestSCEPIsOffUnlessConfigured(t *testing.T) {
	env := newTestEnv(t) // no SCEP
	for _, query := range []string{"?operation=GetCACaps", "?operation=GetCACert", "?operation=PKIOperation"} {
		rec := httptest.NewRecorder()
		env.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, scep.Path+query, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", query, rec.Code)
		}
	}
}
