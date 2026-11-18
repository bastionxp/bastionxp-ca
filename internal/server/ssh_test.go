// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
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
	"github.com/bastionxp/bastionxp-ca/internal/token"
)

// signSSH sends a request to POST /v1/ssh/sign and returns the response.
func (e *testEnv) signSSH(t *testing.T, tok string, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, api.SignSSHPath, bytes.NewReader(data))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

// newSSHPublicKey returns a new SSH public key as one line of text, like
// the content of an id_ed25519.pub file.
func newSSHPublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " alice@laptop\n"
}

// wantSSHCert checks for a 201 response and returns the certificate in it.
func wantSSHCert(t *testing.T, rec *httptest.ResponseRecorder) *ssh.Certificate {
	t.Helper()
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body: %s)", rec.Code, rec.Body)
	}
	var resp api.SignSSHResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf("response is not an SSH certificate: %v (%s)", err, resp.Certificate)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("response is a %T, want an SSH certificate", parsed)
	}
	return cert
}

// An ssh-user token gets a user certificate for the key sent, signed by the
// user CA key, with all of the token's principals and a key ID that starts
// with the token's subject.
func TestSignSSHUser(t *testing.T) {
	env := newTestEnv(t)
	tok := env.issueToken(t, "ssh-user", "alice", "deploy")
	publicKey := newSSHPublicKey(t)

	cert := wantSSHCert(t, env.signSSH(t, tok, api.SignSSHRequest{PublicKey: publicKey}))

	if cert.CertType != ssh.UserCert {
		t.Errorf("certificate type = %d, want a user certificate", cert.CertType)
	}
	// No principals were asked for, so the certificate gets all of the token's.
	if want := []string{"alice", "deploy"}; !reflect.DeepEqual(cert.ValidPrincipals, want) {
		t.Errorf("principals = %v, want %v", cert.ValidPrincipals, want)
	}
	// No subject was given for the token, so its first name is used.
	if !strings.HasPrefix(cert.KeyId, "alice-") {
		t.Errorf("key ID = %q, want it to start with the token's first name, alice", cert.KeyId)
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), env.ca.SSHUserCAPublicKey().Marshal()) {
		t.Error("the certificate is not signed by the SSH user CA key")
	}
	wantKey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(publicKey))
	if !bytes.Equal(cert.Key.Marshal(), wantKey.Marshal()) {
		t.Error("the certificate is for a different key than the one sent")
	}
	validity := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second
	if got := validity.Round(time.Hour); got != ca.SSHUser.DefaultValidity {
		t.Errorf("validity = %s, want %s", got, ca.SSHUser.DefaultValidity)
	}

	// An SSH server that trusts the user CA key must accept the certificate.
	checker := &ssh.CertChecker{
		IsUserAuthority: func(key ssh.PublicKey) bool {
			return bytes.Equal(key.Marshal(), env.ca.SSHUserCAPublicKey().Marshal())
		},
	}
	if err := checker.CheckCert("deploy", cert); err != nil {
		t.Errorf("certificate is not accepted for the principal deploy: %v", err)
	}
	if err := checker.CheckCert("root", cert); err == nil {
		t.Error("certificate is accepted for the principal root")
	}
}

// An ssh-host token gets a host certificate signed by the host CA key, for
// the host name.
func TestSignSSHHost(t *testing.T) {
	env := newTestEnv(t)
	tok := env.issueToken(t, "ssh-host", "web1.example.com")

	cert := wantSSHCert(t, env.signSSH(t, tok, api.SignSSHRequest{PublicKey: newSSHPublicKey(t)}))

	if cert.CertType != ssh.HostCert {
		t.Errorf("certificate type = %d, want a host certificate", cert.CertType)
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), env.ca.SSHHostCAPublicKey().Marshal()) {
		t.Error("the certificate is not signed by the SSH host CA key")
	}
	if want := []string{"web1.example.com"}; !reflect.DeepEqual(cert.ValidPrincipals, want) {
		t.Errorf("principals = %v, want %v", cert.ValidPrincipals, want)
	}
}

// A request may ask for fewer principals than the token gives and a shorter
// lifetime; the key ID still names who the token was for.
func TestSignSSHWithFewerPrincipalsAndValidity(t *testing.T) {
	env := newTestEnv(t)
	tok := env.issueToken(t, "ssh-user", "alice", "deploy")

	cert := wantSSHCert(t, env.signSSH(t, tok, api.SignSSHRequest{
		PublicKey:  newSSHPublicKey(t),
		Principals: []string{"deploy"},
		Validity:   "1h",
	}))

	if want := []string{"deploy"}; !reflect.DeepEqual(cert.ValidPrincipals, want) {
		t.Errorf("principals = %v, want %v", cert.ValidPrincipals, want)
	}
	// The key ID still names who the token was made for.
	if !strings.HasPrefix(cert.KeyId, "alice-") {
		t.Errorf("key ID = %q, want it to start with alice", cert.KeyId)
	}
	validity := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second
	if got := validity.Round(time.Hour); got != time.Hour {
		t.Errorf("validity = %s, want 1h", got)
	}
}

// The key ID tells an SSH server's log who logged in. It must name the
// person the token was made for, also when the login name is shared.
func TestSignSSHKeyIDIsSubjectAndTokenID(t *testing.T) {
	env := newTestEnv(t)
	issue := func() (string, string) {
		tok, err := env.tokens.Issue(token.Options{
			Subject: "alice@example.com", Template: "ssh-user", Names: []string{"deploy"},
		})
		if err != nil {
			t.Fatal(err)
		}
		grant, err := env.tokens.Verify(tok)
		if err != nil {
			t.Fatal(err)
		}
		return tok, grant.ID
	}

	tok, tokenID := issue()
	cert := wantSSHCert(t, env.signSSH(t, tok, api.SignSSHRequest{PublicKey: newSSHPublicKey(t)}))
	if want := "alice@example.com-" + tokenID; cert.KeyId != want {
		t.Errorf("key ID = %q, want %q", cert.KeyId, want)
	}
	// The subject is only a label. It must not become a login name.
	if want := []string{"deploy"}; !reflect.DeepEqual(cert.ValidPrincipals, want) {
		t.Errorf("principals = %v, want %v", cert.ValidPrincipals, want)
	}

	// A second certificate for the same person has its own key ID.
	tok2, _ := issue()
	cert2 := wantSSHCert(t, env.signSSH(t, tok2, api.SignSSHRequest{PublicKey: newSSHPublicKey(t)}))
	if cert2.KeyId == cert.KeyId {
		t.Errorf("two certificates share the key ID %q", cert.KeyId)
	}
}

// A token gets one SSH certificate; a second request with it is refused as
// already used.
func TestSignSSHTokenWorksOnlyOnce(t *testing.T) {
	env := newTestEnv(t)
	tok := env.issueToken(t, "ssh-user", "alice")
	body := api.SignSSHRequest{PublicKey: newSSHPublicKey(t)}

	wantSSHCert(t, env.signSSH(t, tok, body))
	wantError(t, env.signSSH(t, tok, body), http.StatusUnauthorized, "already used")
}

// An SSH request without a token is refused with 401.
func TestSignSSHRejectsMissingToken(t *testing.T) {
	env := newTestEnv(t)
	rec := env.signSSH(t, "", api.SignSSHRequest{PublicKey: newSSHPublicKey(t)})
	wantError(t, rec, http.StatusUnauthorized, "token")
}

// Another principal, an extra one, or one in another letter case is refused
// with 403, and the token still works afterwards.
func TestSignSSHRejectsPrincipalsNotInToken(t *testing.T) {
	env := newTestEnv(t)

	tests := map[string][]string{
		"other principal":       {"root"},
		"extra principal":       {"alice", "root"},
		"different letter case": {"Alice"},
	}
	for name, principals := range tests {
		t.Run(name, func(t *testing.T) {
			tok := env.issueToken(t, "ssh-user", "alice")
			publicKey := newSSHPublicKey(t)

			rec := env.signSSH(t, tok, api.SignSSHRequest{PublicKey: publicKey, Principals: principals})
			wantError(t, rec, http.StatusForbidden, "not allowed")

			// A refused request must not use up the token.
			wantSSHCert(t, env.signSSH(t, tok, api.SignSSHRequest{PublicKey: publicKey}))
		})
	}
}

// A token for one kind of certificate must not work for another kind.
func TestTokensOnlyWorkForTheirOwnKindOfCertificate(t *testing.T) {
	env := newTestEnv(t)

	// A TLS token at the SSH endpoint.
	tlsToken := env.issueToken(t, "tls-server", "web.example.com")
	rec := env.signSSH(t, tlsToken, api.SignSSHRequest{PublicKey: newSSHPublicKey(t)})
	wantError(t, rec, http.StatusForbidden, "tls-server")

	// An SSH token at the TLS endpoint.
	sshToken := env.issueToken(t, "ssh-host", "web.example.com")
	rec = env.sign(t, sshToken, api.SignX509Request{CSR: newCSR(t, "", "web.example.com")})
	wantError(t, rec, http.StatusForbidden, "ssh-host")
}

// Malformed SSH requests are refused with 400 and a message: no public key,
// something that is not a key, a 1024-bit RSA key, a certificate sent as a
// key, and the other cases in the table.
func TestSignSSHRejectsBadRequests(t *testing.T) {
	env := newTestEnv(t)

	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakPub, err := ssh.NewPublicKey(weakRSA.Public())
	if err != nil {
		t.Fatal(err)
	}
	weakKey := string(ssh.MarshalAuthorizedKey(weakPub))

	// An existing certificate, sent as if it were a public key.
	certTok := env.issueToken(t, "ssh-user", "alice")
	existing := wantSSHCert(t, env.signSSH(t, certTok, api.SignSSHRequest{PublicKey: newSSHPublicKey(t)}))
	certAsKey := string(ssh.MarshalAuthorizedKey(existing))

	goodKey := newSSHPublicKey(t)
	tests := []struct {
		name     string
		body     any
		wantText string
	}{
		{"no public key", api.SignSSHRequest{}, "public_key"},
		{"not a public key", api.SignSSHRequest{PublicKey: "hello"}, "not an SSH public key"},
		{"weak key", api.SignSSHRequest{PublicKey: weakKey}, "1024 bits"},
		{"certificate instead of key", api.SignSSHRequest{PublicKey: certAsKey}, "is an SSH certificate"},
		{"validity is not a duration", api.SignSSHRequest{PublicKey: goodKey, Validity: "tomorrow"}, "validity"},
		{"validity above the maximum", api.SignSSHRequest{PublicKey: goodKey, Validity: "9000h"}, "above the maximum"},
		{"unknown field", map[string]string{"public_key": goodKey, "key_id": "root"}, "unknown field"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := env.issueToken(t, "ssh-user", "alice")
			wantError(t, env.signSSH(t, tok, tt.body), http.StatusBadRequest, tt.wantText)
		})
	}
}
