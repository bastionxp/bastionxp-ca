// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/ocsp"
	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// issue gets a certificate through the API, as a client would.
func (e *testEnv) issue(t testing.TB, name string) *x509.Certificate {
	t.Helper()
	tok := e.issueToken(t, "tls-server", name)
	rec := e.sign(t, tok, api.SignX509Request{CSR: newCSR(t, "", name)})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body)
	}
	var resp api.SignX509Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return parseCerts(t, resp.Certificate)[0]
}

// revoke does what "bxp revoke" does on the CA machine.
func (e *testEnv) revoke(t *testing.T, cert *x509.Certificate, reason int) {
	t.Helper()
	if _, err := e.store.RevokeX509(context.Background(), store.X509Serial(cert.SerialNumber), reason); err != nil {
		t.Fatal(err)
	}
}

// fetch sends a GET to the handler and returns the response.
func fetch(t *testing.T, handler http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// crl fetches the CRL and checks its signature, as a relying party does.
func (e *testEnv) crl(t *testing.T) *x509.RevocationList {
	t.Helper()
	rec := fetch(t, e.handler, ca.CRLPath)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/pkix-crl" {
		t.Fatalf("CRL: status %d, type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	crl, err := x509.ParseRevocationList(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(e.ca.IntermediateCert()); err != nil {
		t.Fatalf("the CRL is not signed by the CA: %v", err)
	}
	return crl
}

func onCRL(crl *x509.RevocationList, cert *x509.Certificate) *x509.RevocationListEntry {
	for i := range crl.RevokedCertificateEntries {
		if crl.RevokedCertificateEntries[i].SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return &crl.RevokedCertificateEntries[i]
		}
	}
	return nil
}

// ocspStatus asks about a certificate with a POST and checks the answer's
// signature, as a relying party does.
func (e *testEnv) ocspStatus(t *testing.T, cert, issuer *x509.Certificate) *ocsp.Response {
	t.Helper()
	reqDER, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, ca.OCSPPath, bytes.NewReader(reqDER)))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/ocsp-response" {
		t.Fatalf("OCSP: status %d, type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	resp, err := ocsp.ParseResponseForCert(rec.Body.Bytes(), cert, e.ca.IntermediateCert())
	if err != nil {
		t.Fatalf("the OCSP answer cannot be checked against the CA: %v", err)
	}
	return resp
}

// The public endpoints serve the root and intermediate certificates and the
// SSH user and host CA public keys, and never a private key.
func TestCACertificatesAndSSHKeys(t *testing.T) {
	env := newTestEnv(t)

	for path, want := range map[string]*x509.Certificate{
		ca.RootCertPath:         env.ca.RootCert(),
		ca.IntermediateCertPath: env.ca.IntermediateCert(),
	} {
		rec := fetch(t, env.handler, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		certs := parseCerts(t, rec.Body.String())
		if len(certs) != 1 || !certs[0].Equal(want) {
			t.Errorf("%s does not return the expected certificate", path)
		}
		// A private key must never come out of here.
		if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
			t.Errorf("%s contains a private key", path)
		}
	}

	for path, want := range map[string]ssh.PublicKey{
		SSHUserCAPath: env.ca.SSHUserCAPublicKey(),
		SSHHostCAPath: env.ca.SSHHostCAPublicKey(),
	} {
		rec := fetch(t, env.handler, path)
		got, _, _, _, err := ssh.ParseAuthorizedKey(rec.Body.Bytes())
		if err != nil || !bytes.Equal(got.Marshal(), want.Marshal()) {
			t.Errorf("%s does not return the expected SSH key (error %v)", path, err)
		}
	}
}

// An issued certificate can be downloaded by its serial number, written in
// lower or upper case or with 0x; an unknown serial number is not found, and
// text that is not one is refused.
func TestDownloadCertificate(t *testing.T) {
	env := newTestEnv(t)
	cert := env.issue(t, "web.example.com")
	serial := cert.SerialNumber.Text(16)

	// The serial number is accepted the way people write it.
	for _, written := range []string{serial, strings.ToUpper(serial), "0x" + serial} {
		rec := fetch(t, env.handler, CertificatesPath+written)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d (body: %s)", written, rec.Code, rec.Body)
		}
		got := parseCerts(t, rec.Body.String())
		if len(got) != 1 || !got[0].Equal(cert) {
			t.Errorf("%s: not the certificate that was issued", written)
		}
	}

	wantError(t, fetch(t, env.handler, CertificatesPath+"123456"), http.StatusNotFound, "no certificate")
	wantError(t, fetch(t, env.handler, CertificatesPath+"not-a-serial"), http.StatusBadRequest, "serial number")
}

// The CRL lists a revoked certificate, with its reason, in the very next
// CRL, and lists nothing that was not revoked.
func TestCRL(t *testing.T) {
	env := newTestEnv(t)
	good := env.issue(t, "good.example.com")
	bad := env.issue(t, "bad.example.com")

	if n := len(env.crl(t).RevokedCertificateEntries); n != 0 {
		t.Fatalf("the CRL lists %d certificates before anything was revoked", n)
	}

	env.revoke(t, bad, ca.ReasonKeyCompromise)

	// The very next CRL has it: there is no waiting for a new list.
	crl := env.crl(t)
	entry := onCRL(crl, bad)
	if entry == nil {
		t.Fatal("the revoked certificate is not on the CRL")
	}
	if entry.ReasonCode != ca.ReasonKeyCompromise {
		t.Errorf("reason = %d, want key compromise", entry.ReasonCode)
	}
	if onCRL(crl, good) != nil {
		t.Error("a certificate that was not revoked is on the CRL")
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Errorf("the CRL lists %d certificates, want 1", len(crl.RevokedCertificateEntries))
	}
}

// OCSP answers good for a fresh certificate, revoked with the reason after a
// revocation, and still good for the other certificates.
func TestOCSP(t *testing.T) {
	env := newTestEnv(t)
	issuer := env.ca.IntermediateCert()
	good := env.issue(t, "good.example.com")
	bad := env.issue(t, "bad.example.com")

	if got := env.ocspStatus(t, good, issuer).Status; got != ocsp.Good {
		t.Errorf("a fresh certificate: status %d, want good", got)
	}

	env.revoke(t, bad, ca.ReasonKeyCompromise)
	resp := env.ocspStatus(t, bad, issuer)
	if resp.Status != ocsp.Revoked || resp.RevocationReason != ca.ReasonKeyCompromise {
		t.Errorf("the revoked certificate: status %d, reason %d; want revoked, key compromise", resp.Status, resp.RevocationReason)
	}
	if got := env.ocspStatus(t, good, issuer).Status; got != ocsp.Good {
		t.Errorf("the other certificate after the revocation: status %d, want good", got)
	}
}

// A certificate that is not in the CA's list must never get the answer
// "good", even if it looks as if this CA had issued it.
func TestOCSPForCertificatesTheCADoesNotKnow(t *testing.T) {
	env := newTestEnv(t)
	issuer := env.ca.IntermediateCert()

	// Signed with the CA's own key, but behind the list's back: what a
	// thief of the key would produce.
	env.ca.Record(nil)
	unrecorded, err := env.ca.IssueX509(ca.X509Request{
		Template: ca.TLSServer, PublicKey: mustLeafKey(t).Public(), DNSNames: []string{"rogue.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := env.ocspStatus(t, unrecorded, issuer).Status; got != ocsp.Unknown {
		t.Errorf("a certificate that is not in the list: status %d, want unknown", got)
	}

}

// OCSP answers unknown for a certificate of another CA.
func TestOCSPForAnotherCA(t *testing.T) {
	env := newTestEnv(t)
	other := newTestEnv(t)
	theirs := other.issue(t, "web.example.com")

	// Ask this CA about the other CA's certificate. The request names
	// the other CA as the issuer, so the answer is not signed for it
	// in a way a client would accept; ask and parse by hand.
	reqDER, err := ocsp.CreateRequest(theirs, other.ca.IntermediateCert(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, ca.OCSPPath, bytes.NewReader(reqDER)))
	resp, err := ocsp.ParseResponse(rec.Body.Bytes(), env.ca.IntermediateCert())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != ocsp.Unknown {
		t.Errorf("a certificate of another CA: status %d, want unknown", resp.Status)
	}
}

// The same serial number at another CA must not borrow this CA's "good".
func TestOCSPDoesNotAnswerForASerialNumberAlone(t *testing.T) {
	env := newTestEnv(t)
	other := newTestEnv(t)
	ours := env.issue(t, "web.example.com")

	// A request with our certificate's serial number, but naming the
	// other CA as its issuer.
	fake := *ours
	reqDER, err := ocsp.CreateRequest(&fake, other.ca.IntermediateCert(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, ca.OCSPPath, bytes.NewReader(reqDER)))
	resp, err := ocsp.ParseResponse(rec.Body.Bytes(), env.ca.IntermediateCert())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != ocsp.Unknown {
		t.Errorf("status %d, want unknown", resp.Status)
	}
}

// OCSP over GET with a SHA-256 request, its base64 escaped, plain or URL-
// safe, answers revoked for a revoked certificate.
func TestOCSPWithGETAndSHA256(t *testing.T) {
	env := newTestEnv(t)
	cert := env.issue(t, "web.example.com")
	env.revoke(t, cert, ca.ReasonSuperseded)

	reqDER, err := ocsp.CreateRequest(cert, env.ca.IntermediateCert(), &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	// Base64 has "/" and "+" in it, which must survive as part of an address.
	for name, encoded := range map[string]string{
		"escaped":  url.PathEscape(base64.StdEncoding.EncodeToString(reqDER)),
		"plain":    base64.StdEncoding.EncodeToString(reqDER),
		"URL-safe": base64.URLEncoding.EncodeToString(reqDER),
	} {
		rec := fetch(t, env.handler, ca.OCSPPath+"/"+encoded)
		resp, err := ocsp.ParseResponseForCert(rec.Body.Bytes(), cert, env.ca.IntermediateCert())
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if resp.Status != ocsp.Revoked {
			t.Errorf("%s: status %d, want revoked", name, resp.Status)
		}
	}
}

// An empty, non-OCSP or too large OCSP request, and a GET with bad base64,
// get the standard malformed-request answer.
func TestOCSPMalformedRequests(t *testing.T) {
	env := newTestEnv(t)
	for name, body := range map[string][]byte{
		"empty":     nil,
		"not OCSP":  []byte("hello"),
		"too large": bytes.Repeat([]byte("a"), maxOCSPRequestBytes+1),
	} {
		rec := httptest.NewRecorder()
		env.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, ca.OCSPPath, bytes.NewReader(body)))
		if !bytes.Equal(rec.Body.Bytes(), ocsp.MalformedRequestErrorResponse) {
			t.Errorf("%s: not the 'malformed request' answer", name)
		}
	}
	rec := fetch(t, env.handler, ca.OCSPPath+"/not-base64!")
	if !bytes.Equal(rec.Body.Bytes(), ocsp.MalformedRequestErrorResponse) {
		t.Error("GET with bad base64: not the 'malformed request' answer")
	}
}

// Every way of getting a certificate ends up in the list.
func TestIssuedCertificatesAreInTheList(t *testing.T) {
	env := newTestEnv(t)
	x509Cert := env.issue(t, "web.example.com")
	sshTok := env.issueToken(t, "ssh-user", "alice")
	sshCert := wantSSHCert(t, env.signSSH(t, sshTok, api.SignSSHRequest{PublicKey: newSSHPublicKey(t)}))

	certs, err := env.store.Certificates(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]store.Certificate{}
	for _, cert := range certs {
		found[cert.Kind+":"+cert.Template] = cert
	}
	if got := found["x509:tls-server"]; got.Serial != x509Cert.SerialNumber.Text(16) {
		t.Errorf("the TLS certificate is not in the list: %+v", certs)
	}
	if got := found["ssh:ssh-user"]; got.Subject != sshCert.KeyId {
		t.Errorf("the SSH certificate is not in the list: %+v", certs)
	}
}

// The plain HTTP address serves the public information and nothing else.
func TestPublicHandlerHasOnlyPublicInformation(t *testing.T) {
	env := newTestEnv(t)
	public := env.server.PublicHandler()
	cert := env.issue(t, "web.example.com")

	for _, path := range []string{ca.RootCertPath, ca.IntermediateCertPath, SSHUserCAPath, SSHHostCAPath,
		ca.CRLPath, CertificatesPath + cert.SerialNumber.Text(16)} {
		if rec := fetch(t, public, path); rec.Code != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200", path, rec.Code)
		}
	}

	// Nothing that issues certificates or takes tokens may be reachable
	// without TLS.
	tok := env.issueToken(t, "tls-server", "web.example.com")
	body, _ := json.Marshal(api.SignX509Request{CSR: newCSR(t, "", "web.example.com")})
	for _, path := range []string{api.SignX509Path, api.SignSSHPath, api.OIDCLoginPath, api.OIDCCallbackPath,
		"/acme/directory", "/acme/new-order", "/scep", api.HealthPath} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			req := httptest.NewRequest(method, path, bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+tok)
			rec := httptest.NewRecorder()
			public.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s on the public handler: status %d, want 404", method, path, rec.Code)
			}
		}
	}
	// And the token was not used up by any of that.
	if rec := env.sign(t, tok, api.SignX509Request{CSR: newCSR(t, "", "web.example.com")}); rec.Code != http.StatusCreated {
		t.Errorf("the token was spent through the public handler: status %d", rec.Code)
	}
}

func mustLeafKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Base64 can contain "//". Such a request must still be answered, not
// redirected. Try many, so that some have it.
func TestOCSPGETWithDoubleSlash(t *testing.T) {
	env := newTestEnv(t)
	sawDoubleSlash := false
	for range 40 {
		cert := env.issue(t, "web.example.com")
		reqDER, err := ocsp.CreateRequest(cert, env.ca.IntermediateCert(), nil)
		if err != nil {
			t.Fatal(err)
		}
		encoded := base64.StdEncoding.EncodeToString(reqDER)
		sawDoubleSlash = sawDoubleSlash || strings.Contains(encoded, "//")
		for _, handler := range []http.Handler{env.handler, env.server.PublicHandler()} {
			rec := fetch(t, handler, ca.OCSPPath+"/"+encoded)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: status %d", encoded, rec.Code)
			}
			if _, err := ocsp.ParseResponseForCert(rec.Body.Bytes(), cert, env.ca.IntermediateCert()); err != nil {
				t.Fatalf("%s: %v", encoded, err)
			}
		}
	}
	t.Logf("a request with // was among them: %v", sawDoubleSlash)
}

// The same by hand, for certain: a path with // in the middle.
func TestOCSPFirstTakesUntidyPaths(t *testing.T) {
	env := newTestEnv(t)
	rec := fetch(t, env.handler, ca.OCSPPath+"/MEow//abc")
	if rec.Code == http.StatusMovedPermanently || rec.Header().Get("Location") != "" {
		t.Errorf("status %d, Location %q: the request was redirected", rec.Code, rec.Header().Get("Location"))
	}
	if !bytes.Equal(rec.Body.Bytes(), ocsp.MalformedRequestErrorResponse) {
		t.Errorf("want the OCSP 'malformed request' answer, got %q", rec.Body.String())
	}
}
