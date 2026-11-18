// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/store"
	"github.com/bastionxp/bastionxp-ca/internal/token"
)

// testEnv is a complete CA with its HTTP handler, in a temporary directory.
type testEnv struct {
	ca      *ca.CA
	tokens  *token.Verifier
	handler http.Handler
	store   *store.Store // nil in the environments that do not set it
	server  *Server      // likewise
}

func newTestEnv(t testing.TB) *testEnv {
	t.Helper()
	dir := t.TempDir()

	err := ca.Init(dir, ca.InitOptions{Name: "Test", Organization: "Test Org", KeyType: ca.KeyTypeECDSA})
	if err != nil {
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

	// As in the real server: every certificate goes into the database.
	authority.Record(db)

	tokens := token.New(key)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(Options{CA: authority, Tokens: tokens, Store: db, Log: quiet})
	return &testEnv{ca: authority, tokens: tokens, handler: srv.Handler(), store: db, server: srv}
}

// issueToken creates a token like "bxp token" does.
func (e *testEnv) issueToken(t testing.TB, template string, names ...string) string {
	t.Helper()
	tok, err := e.tokens.Issue(token.Options{Template: template, Names: names})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// sign sends a request to POST /v1/x509/sign and returns the response.
func (e *testEnv) sign(t testing.TB, tok string, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, api.SignX509Path, bytes.NewReader(data))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

// newCSR returns a PEM certificate signing request for the given names.
// Names that are IP addresses become IP addresses in the CSR.
func newCSR(t testing.TB, commonName string, names ...string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return csrForKey(t, key, commonName, names...)
}

func csrForKey(t testing.TB, key any, commonName string, names ...string) string {
	t.Helper()
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	for _, name := range names {
		switch ip := net.ParseIP(name); {
		case ip != nil:
			template.IPAddresses = append(template.IPAddresses, ip)
		case strings.Contains(name, "@"):
			template.EmailAddresses = append(template.EmailAddresses, name)
		default:
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// wantError checks the status code and that the JSON error mentions wantText.
func wantError(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantText string) {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, wantStatus, rec.Body)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("error response is not JSON: %s", rec.Body)
	}
	if !strings.Contains(body["error"], wantText) {
		t.Errorf("error = %q, want it to contain %q", body["error"], wantText)
	}
}

// parseCerts reads all certificates from PEM text.
func parseCerts(t testing.TB, pemText string) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	rest := []byte(pemText)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return certs
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, cert)
	}
}

// GET /health answers 200 with {"status":"ok"}.
func TestHealth(t *testing.T) {
	env := newTestEnv(t)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"status":"ok"}` {
		t.Errorf("body = %s", got)
	}
}

// A token and a CSR get a certificate, returned alone and as a chain with
// the intermediate, that verifies for each of its names (DNS and IP) against
// the root as a server certificate.
func TestSignX509(t *testing.T) {
	env := newTestEnv(t)
	tok := env.issueToken(t, "tls-server", "web.example.com", "10.0.0.5")

	rec := env.sign(t, tok, api.SignX509Request{CSR: newCSR(t, "web.example.com", "web.example.com", "10.0.0.5")})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body: %s)", rec.Code, rec.Body)
	}
	var resp api.SignX509Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	certs := parseCerts(t, resp.Certificate)
	if len(certs) != 1 {
		t.Fatalf("certificate has %d PEM blocks, want 1", len(certs))
	}
	cert := certs[0]

	chain := parseCerts(t, resp.Chain)
	if len(chain) != 2 || !chain[0].Equal(cert) || !chain[1].Equal(env.ca.IntermediateCert()) {
		t.Fatal("chain must be the new certificate followed by the intermediate")
	}

	// The certificate must work for a TLS client that only trusts the root.
	roots := x509.NewCertPool()
	roots.AddCert(env.ca.RootCert())
	intermediates := x509.NewCertPool()
	intermediates.AddCert(chain[1])
	for _, host := range []string{"web.example.com", "10.0.0.5"} {
		_, err := cert.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			DNSName:       host,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			t.Errorf("certificate does not verify for %s: %v", host, err)
		}
	}

	// No validity was asked for, so the template's default applies.
	if got := cert.NotAfter.Sub(cert.NotBefore).Round(time.Hour); got != ca.TLSServer.DefaultValidity {
		t.Errorf("validity = %s, want %s", got, ca.TLSServer.DefaultValidity)
	}
}

// A request may ask for a lifetime within the profile's maximum, and gets
// it.
func TestSignX509WithRequestedValidity(t *testing.T) {
	env := newTestEnv(t)
	tok := env.issueToken(t, "tls-server", "web.example.com")

	rec := env.sign(t, tok, api.SignX509Request{CSR: newCSR(t, "", "web.example.com"), Validity: "24h"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body: %s)", rec.Code, rec.Body)
	}
	var resp api.SignX509Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	cert := parseCerts(t, resp.Certificate)[0]
	if got := cert.NotAfter.Sub(cert.NotBefore).Round(time.Hour); got != 24*time.Hour {
		t.Errorf("validity = %s, want 24h", got)
	}
}

// A tls-client token gets a certificate for client authentication only.
func TestSignX509ClientCertificate(t *testing.T) {
	env := newTestEnv(t)
	tok := env.issueToken(t, "tls-client", "alice@example.com")

	rec := env.sign(t, tok, api.SignX509Request{CSR: newCSR(t, "alice@example.com", "alice@example.com")})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body: %s)", rec.Code, rec.Body)
	}
	var resp api.SignX509Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	cert := parseCerts(t, resp.Certificate)[0]
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("extended key usage = %v, want client auth only", cert.ExtKeyUsage)
	}
}

// A token gets one certificate; a second request with it is refused as
// already used.
func TestSignX509TokenWorksOnlyOnce(t *testing.T) {
	env := newTestEnv(t)
	tok := env.issueToken(t, "tls-server", "web.example.com")
	body := api.SignX509Request{CSR: newCSR(t, "", "web.example.com")}

	if rec := env.sign(t, tok, body); rec.Code != http.StatusCreated {
		t.Fatalf("first use: status = %d, want 201 (body: %s)", rec.Code, rec.Body)
	}
	wantError(t, env.sign(t, tok, body), http.StatusUnauthorized, "already used")
}

// A request without a token, with something that is not a token, a token
// signed by another key, or a damaged token is refused with 401.
func TestSignX509RejectsBadTokens(t *testing.T) {
	env := newTestEnv(t)
	body := api.SignX509Request{CSR: newCSR(t, "", "web.example.com")}

	// A token signed with a key that is not the CA's.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := token.New(otherKey).Issue(token.Options{Template: "tls-server", Names: []string{"web.example.com"}})
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]string{
		"no token":      "",
		"not a token":   "hello",
		"forged token":  forged,
		"damaged token": env.issueToken(t, "tls-server", "web.example.com") + "x",
	}
	for name, tok := range tests {
		t.Run(name, func(t *testing.T) {
			wantError(t, env.sign(t, tok, body), http.StatusUnauthorized, "token")
		})
	}
}

// A token sent with another authorization scheme than Bearer is refused.
func TestSignX509RejectsWrongAuthorizationScheme(t *testing.T) {
	env := newTestEnv(t)
	tok := env.issueToken(t, "tls-server", "web.example.com")

	data, _ := json.Marshal(api.SignX509Request{CSR: newCSR(t, "", "web.example.com")})
	req := httptest.NewRequest(http.MethodPost, api.SignX509Path, bytes.NewReader(data))
	req.Header.Set("Authorization", "Basic "+tok)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	wantError(t, rec, http.StatusUnauthorized, "token")
}

// A CSR with another, an extra or a wildcard name, another common name, or
// an extra IP address is refused with 403, and the token still works for a
// corrected request.
func TestSignX509RejectsNamesNotInToken(t *testing.T) {
	env := newTestEnv(t)

	tests := []struct {
		name string
		csr  string
	}{
		{"other DNS name", newCSR(t, "", "db.example.com")},
		{"extra DNS name", newCSR(t, "", "web.example.com", "db.example.com")},
		{"other common name", newCSR(t, "db.example.com", "web.example.com")},
		{"extra IP address", newCSR(t, "", "web.example.com", "10.0.0.5")},
		{"wildcard", newCSR(t, "", "*.example.com")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := env.issueToken(t, "tls-server", "web.example.com")
			wantError(t, env.sign(t, tok, api.SignX509Request{CSR: tt.csr}), http.StatusForbidden, "not allowed")

			// A refused request must not use up the token: the holder
			// can correct the CSR and try again.
			good := api.SignX509Request{CSR: newCSR(t, "", "web.example.com")}
			if rec := env.sign(t, tok, good); rec.Code != http.StatusCreated {
				t.Errorf("corrected request: status = %d, want 201 (body: %s)", rec.Code, rec.Body)
			}
		})
	}
}

// A token for an SSH profile cannot get a TLS certificate.
func TestSignX509RejectsTokenForUnknownTemplate(t *testing.T) {
	env := newTestEnv(t)
	// "ssh-user" is a real template, but not one for X.509 certificates.
	tok := env.issueToken(t, "ssh-user", "alice")

	rec := env.sign(t, tok, api.SignX509Request{CSR: newCSR(t, "alice")})
	wantError(t, rec, http.StatusForbidden, "ssh-user")
}

// Malformed requests are refused with 400 and a message: no CSR, not PEM, a
// certificate instead of a CSR, a broken CSR signature, a bad, negative or
// too long validity, a 1024-bit RSA key, unknown fields, and a body that is
// not JSON.
func TestSignX509RejectsBadRequests(t *testing.T) {
	env := newTestEnv(t)

	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	// A CSR whose signature no longer matches its content.
	tampered := []byte(newCSR(t, "", "web.example.com"))
	block, _ := pem.Decode(tampered)
	block.Bytes[len(block.Bytes)-1] ^= 0xff
	tamperedCSR := string(pem.EncodeToMemory(block))

	goodCSR := newCSR(t, "", "web.example.com")
	tests := []struct {
		name     string
		body     any
		wantText string
	}{
		{"no CSR", api.SignX509Request{}, "csr"},
		{"CSR is not PEM", api.SignX509Request{CSR: "hello"}, "PEM"},
		{"CSR is a certificate", api.SignX509Request{CSR: string(ca.EncodeCertPEM(env.ca.RootCert()))}, "PEM certificate signing request"},
		{"CSR with broken signature", api.SignX509Request{CSR: tamperedCSR}, "CSR"},
		{"validity is not a duration", api.SignX509Request{CSR: goodCSR, Validity: "tomorrow"}, "validity"},
		{"validity above the maximum", api.SignX509Request{CSR: goodCSR, Validity: "20000h"}, "above the maximum"},
		{"negative validity", api.SignX509Request{CSR: goodCSR, Validity: "-1h"}, "must be positive"},
		{"weak key", api.SignX509Request{CSR: csrForKey(t, weakKey, "", "web.example.com")}, "1024 bits"},
		{"unknown field", map[string]string{"csr": goodCSR, "template": "tls-client"}, "unknown field"},
		{"body is not an object", "hello", "invalid JSON"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := env.issueToken(t, "tls-server", "web.example.com")
			wantError(t, env.sign(t, tok, tt.body), http.StatusBadRequest, tt.wantText)
		})
	}
}

// A server certificate needs a DNS name or IP address, not only a common
// name.
func TestSignX509ServerCertificateNeedsAHostName(t *testing.T) {
	env := newTestEnv(t)
	tok := env.issueToken(t, "tls-server", "web.example.com")

	// Only a common name: fine for a client, not enough for a server.
	rec := env.sign(t, tok, api.SignX509Request{CSR: newCSR(t, "web.example.com")})
	wantError(t, rec, http.StatusBadRequest, "DNS name or IP address")
}

// A request body above the size limit is refused.
func TestSignX509RejectsLargeBody(t *testing.T) {
	env := newTestEnv(t)
	tok := env.issueToken(t, "tls-server", "web.example.com")

	rec := env.sign(t, tok, api.SignX509Request{CSR: strings.Repeat("x", maxBodyBytes+1)})
	wantError(t, rec, http.StatusBadRequest, "too large")
}

// Unknown addresses answer 404, and known ones with the wrong method 405.
func TestUnknownRoutes(t *testing.T) {
	env := newTestEnv(t)
	tests := []struct {
		method, path string
		wantStatus   int
	}{
		{http.MethodGet, "/nothing-here", http.StatusNotFound},
		{http.MethodGet, api.SignX509Path, http.StatusMethodNotAllowed},
		{http.MethodPost, "/health", http.StatusMethodNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			env.handler.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}
