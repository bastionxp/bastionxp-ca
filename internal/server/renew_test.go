// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/client"
	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// issueWithKey gets a TLS certificate with a token and keeps its key.
func (e *testEnv) issueWithKey(t testing.TB, template, validity string, names ...string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key := mustLeafKey(t)
	tok := e.issueToken(t, template, names...)
	rec := e.sign(t, tok, api.SignX509Request{CSR: csrForKey(t, key, names[0], names...), Validity: validity})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body)
	}
	var resp api.SignX509Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return parseCerts(t, resp.Certificate)[0], key
}

// renewBody returns the body of a TLS renewal for a new key.
func renewBody(t testing.TB, names ...string) []byte {
	t.Helper()
	body, err := json.Marshal(api.RenewX509Request{CSR: newCSR(t, "", names...)})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// renew sends a renew request with a proof and a body.
func (e *testEnv) renew(t *testing.T, path, proof string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+proof)
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

func mustProof(t testing.TB, p client.Proof) string {
	t.Helper()
	proof, err := p.Sign()
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

// Renewing a TLS certificate with a proof signed by its key: the new
// certificate has a new serial number and a new key, keeps the old one's
// names, kind and lifetime whatever names the request asks for, and is in
// the list of issued certificates.
func TestRenewX509(t *testing.T) {
	env := newTestEnv(t)
	old, key := env.issueWithKey(t, "tls-server", "48h", "web.example.com", "10.0.0.5")

	// The body asks for other names. They must be ignored.
	body := renewBody(t, "evil.example.com")
	rec := env.renew(t, api.RenewX509Path, mustProof(t, client.Proof{Key: key, X509: old, Body: body}), body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body)
	}
	var resp api.SignX509Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	renewed := parseCerts(t, resp.Certificate)[0]

	if renewed.SerialNumber.Cmp(old.SerialNumber) == 0 {
		t.Error("the renewed certificate has the old serial number")
	}
	if renewed.Subject.CommonName != old.Subject.CommonName || !reflect.DeepEqual(renewed.DNSNames, old.DNSNames) ||
		len(renewed.IPAddresses) != 1 || !renewed.IPAddresses[0].Equal(old.IPAddresses[0]) {
		t.Errorf("names changed: %q %v %v, want %q %v %v",
			renewed.Subject.CommonName, renewed.DNSNames, renewed.IPAddresses, old.Subject.CommonName, old.DNSNames, old.IPAddresses)
	}
	if !reflect.DeepEqual(renewed.ExtKeyUsage, old.ExtKeyUsage) {
		t.Errorf("kind changed: %v, want %v", renewed.ExtKeyUsage, old.ExtKeyUsage)
	}
	if sameKey(renewed.PublicKey, old.PublicKey) {
		t.Error("the renewed certificate has the old key")
	}
	// As long as the old one, not the template's 90 days.
	if got := renewed.NotAfter.Sub(renewed.NotBefore).Round(time.Hour); got != 48*time.Hour {
		t.Errorf("lifetime = %s, want 48h like the old certificate", got)
	}
	// And it is in the list, so it can be renewed or revoked in turn.
	if _, err := env.store.Certificate(context.Background(), store.KindX509, store.X509Serial(renewed.SerialNumber)); err != nil {
		t.Errorf("the renewed certificate is not in the list: %v", err)
	}
}

// The road from a client's point of view, with the client package.
func TestRenewX509WithTheClient(t *testing.T) {
	env := newTestEnv(t)
	old, key := env.issueWithKey(t, "tls-client", "", "alice@example.com")
	ts := httptest.NewTLSServer(env.handler)
	defer ts.Close()
	c, err := client.New(ts.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	c = client.WithHTTPClient(c, ts.Client())

	newKey := mustLeafKey(t)
	resp, err := c.RenewX509(context.Background(), old, key, csrForKey(t, newKey, "", "alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	renewed := parseCerts(t, resp.Certificate)[0]
	if !sameKey(renewed.PublicKey, newKey.Public()) {
		t.Error("the certificate is not for the new key")
	}
	// The renewed certificate renews in turn.
	again, err := c.RenewX509(context.Background(), renewed, newKey, newCSR(t, ""))
	if err != nil {
		t.Errorf("renewing the renewed certificate: %v", err)
	} else if parseCerts(t, again.Certificate)[0].SerialNumber.Cmp(renewed.SerialNumber) == 0 {
		t.Error("no new certificate")
	}
}

// Every way a TLS renewal is refused, with its status and message: no proof
// or a malformed one, a proof signed with another key, a certificate of
// another CA or one missing from the list, a proof for another request body
// or for SSH, one that lives too long or has expired, the same key again, a
// bad CSR or an unknown field. A correct request still works afterwards.
func TestRenewX509Refusals(t *testing.T) {
	env := newTestEnv(t)
	old, key := env.issueWithKey(t, "tls-server", "", "web.example.com")
	thief := mustLeafKey(t)
	other := newTestEnv(t)
	foreign, foreignKey := other.issueWithKey(t, "tls-server", "", "web.example.com")

	// Signed with our CA's key, but behind the list's back.
	env.ca.Record(nil)
	unrecorded, err := env.ca.IssueX509(ca.X509Request{Template: ca.TLSServer, PublicKey: thief.Public(), DNSNames: []string{"web.example.com"}})
	env.ca.Record(env.store)
	if err != nil {
		t.Fatal(err)
	}

	body := renewBody(t)
	sameKeyBody, _ := json.Marshal(api.RenewX509Request{CSR: csrForKey(t, key, "")})

	tests := []struct {
		name       string
		proof      string
		body       []byte
		wantStatus int
		wantText   string
	}{
		{"no proof", "", body, http.StatusUnauthorized, "proof"},
		{"not a proof", "hello", body, http.StatusUnauthorized, "proof"},
		// Someone who has the public certificate, but not the key.
		{"signed with another key", mustProof(t, client.Proof{Key: thief, X509: old, Body: body}), body, http.StatusUnauthorized, "not signed with the certificate's key"},
		{"certificate of another CA", mustProof(t, client.Proof{Key: foreignKey, X509: foreign, Body: body}), body, http.StatusUnauthorized, "not a valid certificate of this CA"},
		{"certificate not in the list", mustProof(t, client.Proof{Key: thief, X509: unrecorded, Body: body}), body, http.StatusForbidden, "no record"},
		{"proof for another body", mustProof(t, client.Proof{Key: key, X509: old, Body: renewBody(t)}), body, http.StatusUnauthorized, "another request"},
		{"proof for SSH", mustProof(t, client.Proof{Key: key, X509: old, Body: body, Audience: api.ProofAudienceSSH}), body, http.StatusUnauthorized, "meant for something else"},
		{"proof that lives too long", mustProof(t, client.Proof{Key: key, X509: old, Body: body, Lifetime: time.Hour}), body, http.StatusUnauthorized, "within 5 minutes"},
		{"proof that has expired", mustProof(t, client.Proof{Key: key, X509: old, Body: body, Now: time.Now().Add(-10 * time.Minute)}), body, http.StatusUnauthorized, "expired"},
		{"the same key again", mustProof(t, client.Proof{Key: key, X509: old, Body: sameKeyBody}), sameKeyBody, http.StatusBadRequest, "new key"},
		{"not a CSR", mustProof(t, client.Proof{Key: key, X509: old, Body: []byte(`{"csr":"hello"}`)}), []byte(`{"csr":"hello"}`), http.StatusBadRequest, "csr"},
		{"unknown field", mustProof(t, client.Proof{Key: key, X509: old, Body: []byte(`{"csr":"x","names":["evil"]}`)}), []byte(`{"csr":"x","names":["evil"]}`), http.StatusBadRequest, "unknown field"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantError(t, env.renew(t, api.RenewX509Path, tt.proof, tt.body), tt.wantStatus, tt.wantText)
		})
	}

	// None of that spent anything: the real request still works.
	if rec := env.renew(t, api.RenewX509Path, mustProof(t, client.Proof{Key: key, X509: old, Body: body}), body); rec.Code != http.StatusCreated {
		t.Errorf("the correct request after the refusals: status %d (body: %s)", rec.Code, rec.Body)
	}
}

// A renewal proof works only once: the same request sent again is refused as
// already used.
func TestRenewX509ProofWorksOnce(t *testing.T) {
	env := newTestEnv(t)
	old, key := env.issueWithKey(t, "tls-server", "", "web.example.com")
	body := renewBody(t)
	proof := mustProof(t, client.Proof{Key: key, X509: old, Body: body})

	if rec := env.renew(t, api.RenewX509Path, proof, body); rec.Code != http.StatusCreated {
		t.Fatalf("first use: status %d (body: %s)", rec.Code, rec.Body)
	}
	// A captured request, sent again.
	wantError(t, env.renew(t, api.RenewX509Path, proof, body), http.StatusUnauthorized, "already used")
}

// A revoked TLS certificate cannot be renewed.
func TestRenewX509RefusesRevokedCertificates(t *testing.T) {
	env := newTestEnv(t)
	old, key := env.issueWithKey(t, "tls-server", "", "web.example.com")
	env.revoke(t, old, ca.ReasonKeyCompromise)

	body := renewBody(t)
	wantError(t, env.renew(t, api.RenewX509Path, mustProof(t, client.Proof{Key: key, X509: old, Body: body}), body),
		http.StatusForbidden, "revoked")
}

// An expired TLS certificate cannot be renewed: it needs a new token.
func TestRenewX509RefusesExpiredCertificates(t *testing.T) {
	env := newTestEnv(t)
	old, key := env.issueWithKey(t, "tls-server", "1s", "web.example.com")
	time.Sleep(time.Until(old.NotAfter) + 100*time.Millisecond)

	body := renewBody(t)
	wantError(t, env.renew(t, api.RenewX509Path, mustProof(t, client.Proof{Key: key, X509: old, Body: body}), body),
		http.StatusUnauthorized, "expired")
}

// issueSSHHost gets an SSH host certificate with a token and keeps the
// host's private key.
func (e *testEnv) issueSSHHost(t *testing.T, principals ...string) (*ssh.Certificate, crypto.Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(pub)
	tok := e.issueToken(t, "ssh-host", principals...)
	cert := wantSSHCert(t, e.signSSH(t, tok, api.SignSSHRequest{PublicKey: string(ssh.MarshalAuthorizedKey(sshPub))}))
	return cert, priv
}

// Renewing an SSH host certificate: a new serial number, the same type, key
// ID and principals, the same host key, signed by the host CA.
func TestRenewSSH(t *testing.T) {
	env := newTestEnv(t)
	old, key := env.issueSSHHost(t, "web1.example.com", "web1")

	body, _ := json.Marshal(api.RenewSSHRequest{})
	rec := env.renew(t, api.RenewSSHPath, mustProof(t, client.Proof{Key: key, SSH: old, Body: body}), body)
	renewed := wantSSHCert(t, rec)

	if renewed.Serial == old.Serial {
		t.Error("the renewed certificate has the old serial number")
	}
	if renewed.CertType != ssh.HostCert || renewed.KeyId != old.KeyId || !reflect.DeepEqual(renewed.ValidPrincipals, old.ValidPrincipals) {
		t.Errorf("renewed = type %d, key ID %q, principals %v; want those of the old one", renewed.CertType, renewed.KeyId, renewed.ValidPrincipals)
	}
	// The same host key: it is what known_hosts and clients know.
	if !bytes.Equal(renewed.Key.Marshal(), old.Key.Marshal()) {
		t.Error("the renewed certificate is for another host key")
	}
	if !bytes.Equal(renewed.SignatureKey.Marshal(), env.ca.SSHHostCAPublicKey().Marshal()) {
		t.Error("not signed by the host CA")
	}
}

// The client library renews an SSH host certificate through a TLS server.
func TestRenewSSHWithTheClient(t *testing.T) {
	env := newTestEnv(t)
	old, key := env.issueSSHHost(t, "web1.example.com")
	ts := httptest.NewTLSServer(env.handler)
	defer ts.Close()
	c, err := client.New(ts.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	c = client.WithHTTPClient(c, ts.Client())

	resp, err := c.RenewSSH(context.Background(), old, key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.Certificate, "-cert-v01@openssh.com") {
		t.Errorf("answer = %q", resp.Certificate)
	}
}

// SSH renewal refuses a user certificate, a host certificate of another CA,
// a proof signed with another key, a proof meant for TLS, and a revoked
// certificate.
func TestRenewSSHRefusals(t *testing.T) {
	env := newTestEnv(t)
	old, key := env.issueSSHHost(t, "web1.example.com")
	body, _ := json.Marshal(api.RenewSSHRequest{})

	// A user certificate.
	_, userKey, _ := ed25519.GenerateKey(rand.Reader)
	userPub, _ := ssh.NewPublicKey(userKey.Public())
	userTok := env.issueToken(t, "ssh-user", "alice")
	user := wantSSHCert(t, env.signSSH(t, userTok, api.SignSSHRequest{PublicKey: string(ssh.MarshalAuthorizedKey(userPub))}))

	// A host certificate of another CA.
	other := newTestEnv(t)
	foreign, foreignKey := other.issueSSHHost(t, "web1.example.com")

	_, thief, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name       string
		proof      string
		wantStatus int
		wantText   string
	}{
		{"user certificate", mustProof(t, client.Proof{Key: userKey, SSH: user, Body: body}), http.StatusForbidden, "only SSH host certificates"},
		{"certificate of another CA", mustProof(t, client.Proof{Key: foreignKey, SSH: foreign, Body: body}), http.StatusUnauthorized, "not from this CA"},
		{"signed with another key", mustProof(t, client.Proof{Key: thief, SSH: old, Body: body}), http.StatusUnauthorized, "not signed with the certificate's key"},
		{"proof for TLS", mustProof(t, client.Proof{Key: key, SSH: old, Body: body, Audience: api.ProofAudienceX509}), http.StatusUnauthorized, "meant for something else"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantError(t, env.renew(t, api.RenewSSHPath, tt.proof, body), tt.wantStatus, tt.wantText)
		})
	}

	// Revoked: renewal is what SSH revocation stops.
	if _, err := env.store.Revoke(context.Background(), store.KindSSH, store.SSHSerial(old.Serial), ca.ReasonKeyCompromise); err != nil {
		t.Fatal(err)
	}
	wantError(t, env.renew(t, api.RenewSSHPath, mustProof(t, client.Proof{Key: key, SSH: old, Body: body}), body),
		http.StatusForbidden, "revoked")
}

// A renewed certificate keeps the old one's lifetime, and gets the profile's
// default when the old lifetime is above the maximum or too short to be
// real.
func TestRenewedValidity(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		lifetime, max, want time.Duration
	}{
		{90*24*time.Hour + time.Minute, 398 * 24 * time.Hour, 90 * 24 * time.Hour},
		{48*time.Hour + time.Minute, 398 * 24 * time.Hour, 48 * time.Hour},
		{400 * 24 * time.Hour, 398 * 24 * time.Hour, 0}, // above the maximum: the default
		{30 * time.Second, time.Hour, 0},                // nonsense: the default
	}
	for _, tt := range tests {
		if got := renewedValidity(start, start.Add(tt.lifetime), tt.max); got != tt.want {
			t.Errorf("lifetime %s: got %s, want %s", tt.lifetime, got, tt.want)
		}
	}
}
