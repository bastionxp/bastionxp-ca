// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
)

// issueTLS gets a TLS certificate from the test CA, like a requester
// with a token does, and returns the leaf and the intermediate.
func (c *testCA) issueTLS(t *testing.T, name string) (leaf, intermediate *x509.Certificate) {
	t.Helper()
	outDir := t.TempDir()
	conn := c.connection(t, "tls-server", name)
	if err := runTLS(context.Background(), io.Discard, conn, tlsOptions{names: []string{name}, outDir: outDir}); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(outDir, name+".crt"), filepath.Join(outDir, name+".key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ = x509.ParseCertificate(pair.Certificate[0])
	intermediate, _ = x509.ParseCertificate(pair.Certificate[1])
	return leaf, intermediate
}

// httpGet fetches an address with plain HTTP.
func httpGet(t *testing.T, address string) []byte {
	t.Helper()
	resp, err := http.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d (%s)", address, resp.StatusCode, body)
	}
	return body
}

// The whole road of a revocation, the way a relying party sees it: the
// certificate says where to ask, and the answers there change within
// seconds of the administrator revoking it.
func TestRevoke(t *testing.T) {
	testCA := startTestCA(t, withPublicHTTP)
	publicURL := testCA.cfg.Server.PublicURL
	cert, intermediate := testCA.issueTLS(t, "web.example.com")
	other, _ := testCA.issueTLS(t, "other.example.com")

	// The certificate carries the addresses to ask at.
	if len(cert.CRLDistributionPoints) != 1 || cert.CRLDistributionPoints[0] != publicURL+ca.CRLPath {
		t.Fatalf("CRL address in the certificate = %v, want %s", cert.CRLDistributionPoints, publicURL+ca.CRLPath)
	}
	if len(cert.OCSPServer) != 1 || cert.OCSPServer[0] != publicURL+ca.OCSPPath {
		t.Fatalf("OCSP address in the certificate = %v", cert.OCSPServer)
	}
	if len(cert.IssuingCertificateURL) != 1 {
		t.Fatalf("issuer address in the certificate = %v", cert.IssuingCertificateURL)
	}

	// A relying party follows them, with plain HTTP and no secrets.
	fetchedIssuer := httpGet(t, cert.IssuingCertificateURL[0])
	if !bytes.Contains(fetchedIssuer, []byte("BEGIN CERTIFICATE")) {
		t.Errorf("the issuer address returns: %s", fetchedIssuer)
	}
	askCRL := func() *x509.RevocationList {
		crl, err := x509.ParseRevocationList(httpGet(t, cert.CRLDistributionPoints[0]))
		if err != nil {
			t.Fatal(err)
		}
		if err := crl.CheckSignatureFrom(intermediate); err != nil {
			t.Fatalf("the CRL is not signed by the CA: %v", err)
		}
		return crl
	}
	askOCSP := func(about *x509.Certificate) int {
		reqDER, err := ocsp.CreateRequest(about, intermediate, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.Post(about.OCSPServer[0], "application/ocsp-request", bytes.NewReader(reqDER))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		answer, err := ocsp.ParseResponseForCert(body, about, intermediate)
		if err != nil {
			t.Fatalf("the OCSP answer cannot be checked against the CA: %v", err)
		}
		return answer.Status
	}

	if n := len(askCRL().RevokedCertificateEntries); n != 0 {
		t.Fatalf("%d certificates on the CRL before the revocation", n)
	}
	if status := askOCSP(cert); status != ocsp.Good {
		t.Fatalf("OCSP before the revocation: %d, want good", status)
	}

	// The administrator revokes it, on the CA machine. The serial number
	// is typed the way openssl prints it: upper case.
	var out bytes.Buffer
	serial := strings.ToUpper(cert.SerialNumber.Text(16))
	if err := runRevoke(context.Background(), &out, testCA.cfg, serial, "key-compromise", false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "web.example.com") || !strings.Contains(out.String(), "key-compromise") {
		t.Errorf("output:\n%s", out.String())
	}

	// The running server shows it within seconds, without a restart: it
	// looks for new revocations every few seconds, then signs anew.
	deadline := time.Now().Add(10 * time.Second)
	for askOCSP(cert) != ocsp.Revoked && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	crl := askCRL()
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("the CRL after the revocation: %+v", crl.RevokedCertificateEntries)
	}
	if status := askOCSP(cert); status != ocsp.Revoked {
		t.Errorf("OCSP after the revocation: %d, want revoked", status)
	}
	// Only that certificate.
	if status := askOCSP(other); status != ocsp.Good {
		t.Errorf("OCSP for another certificate: %d, want good", status)
	}

	// A second time is an error that says when it was done.
	err := runRevoke(context.Background(), io.Discard, testCA.cfg, serial, "superseded", false)
	if err == nil || !strings.Contains(err.Error(), "already revoked") || !strings.Contains(err.Error(), "key-compromise") {
		t.Errorf("second revocation: error = %v", err)
	}
}

// The plain HTTP address must not issue anything.
func TestPublicHTTPAddressOnlyHasPublicInformation(t *testing.T) {
	testCA := startTestCA(t, withPublicHTTP, withSCEP)
	publicURL := testCA.cfg.Server.PublicURL
	conn := testCA.connection(t, "tls-server", "web.example.com")

	for _, path := range []string{"/v1/x509/sign", "/v1/ssh/sign", "/v1/oidc/login", "/acme/directory", "/acme/new-nonce", "/scep?operation=GetCACaps", "/health"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			req, _ := http.NewRequest(method, publicURL+path, strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+conn.token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("%s %s over plain HTTP: status %d, want 404", method, path, resp.StatusCode)
			}
		}
	}
	// The same things do exist on the HTTPS address.
	if err := runTLS(context.Background(), io.Discard, conn, tlsOptions{names: []string{"web.example.com"}, outDir: t.TempDir()}); err != nil {
		t.Errorf("over HTTPS: %v", err)
	}
}

// Without a public address configured, certificates name no addresses.
func TestNoRevocationAddressesUnlessConfigured(t *testing.T) {
	testCA := startTestCA(t)
	cert, _ := testCA.issueTLS(t, "web.example.com")
	if len(cert.CRLDistributionPoints)+len(cert.OCSPServer)+len(cert.IssuingCertificateURL) != 0 {
		t.Errorf("addresses in the certificate: %v %v %v", cert.CRLDistributionPoints, cert.OCSPServer, cert.IssuingCertificateURL)
	}
}

// bxp list certificates shows TLS and SSH certificates, the server's own
// certificate among them; with --revoked, nothing before a revocation,
// then only the revoked certificate with its reason.
func TestList(t *testing.T) {
	testCA := startTestCA(t)
	cert, _ := testCA.issueTLS(t, "web.example.com")

	// An SSH certificate too.
	sshConn := testCA.connection(t, "ssh-user", "alice")
	if err := runSSH(context.Background(), io.Discard, sshConn, sshOptions{keyFile: writeSSHKey(t, t.TempDir())}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runListCertificates(context.Background(), &out, testCA.cfg, false, "text"); err != nil {
		t.Fatal(err)
	}
	listing := out.String()
	for _, want := range []string{cert.SerialNumber.Text(16), "tls-server", "web.example.com", "ssh-user", "alice", "valid"} {
		if !strings.Contains(listing, want) {
			t.Errorf("the list lacks %q:\n%s", want, listing)
		}
	}
	// The server's own certificate is in the list as well: it is a
	// certificate of this CA like any other, and can be revoked.
	if !strings.Contains(listing, "localhost") {
		t.Errorf("the server's own certificate is not in the list:\n%s", listing)
	}

	// Nothing is revoked yet.
	out.Reset()
	if err := runListCertificates(context.Background(), &out, testCA.cfg, true, "text"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No certificates") {
		t.Errorf("the revoked list before any revocation:\n%s", out.String())
	}

	if err := runRevoke(context.Background(), io.Discard, testCA.cfg, cert.SerialNumber.Text(16), "superseded", false); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runListCertificates(context.Background(), &out, testCA.cfg, true, "text"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "web.example.com") || !strings.Contains(out.String(), "revoked") ||
		!strings.Contains(out.String(), "superseded") || strings.Contains(out.String(), "alice") {
		t.Errorf("the revoked list:\n%s", out.String())
	}
}

// bxp revoke refuses an unknown reason, text that is not a serial number,
// and an unknown serial number, and revokes nothing.
func TestRevokeRefusesBadInput(t *testing.T) {
	testCA := startTestCA(t)
	cert, _ := testCA.issueTLS(t, "web.example.com")
	serial := cert.SerialNumber.Text(16)

	// The serial number of an SSH certificate.
	sshConn := testCA.connection(t, "ssh-user", "alice")
	keyFile := writeSSHKey(t, t.TempDir())
	if err := runSSH(context.Background(), io.Discard, sshConn, sshOptions{keyFile: keyFile}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		serial  string
		reason  string
		wantErr string
	}{
		{"unknown reason", serial, "boredom", "unknown reason"},
		{"not a serial number", "web.example.com", "unspecified", "serial number"},
		{"unknown serial number", "abcdef0123", "unspecified", "no TLS certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runRevoke(context.Background(), io.Discard, testCA.cfg, tt.serial, tt.reason, false)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}

	// None of that revoked anything.
	var out bytes.Buffer
	if err := runListCertificates(context.Background(), &out, testCA.cfg, true, "text"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No certificates") {
		t.Errorf("something was revoked:\n%s", out.String())
	}
}

// bxp revoke and bxp list certificates say there is no database for a CA
// that has never run.
func TestRevokeAndListNeedADatabase(t *testing.T) {
	cfg := newTestConfig(t) // a CA that never ran: no database
	if err := runInit(io.Discard, cfg, testInit); err != nil {
		t.Fatal(err)
	}
	if err := runListCertificates(context.Background(), io.Discard, cfg, false, "text"); err == nil || !strings.Contains(err.Error(), "no database") {
		t.Errorf("list: error = %v", err)
	}
	if err := runRevoke(context.Background(), io.Discard, cfg, "abcdef", "unspecified", false); err == nil || !strings.Contains(err.Error(), "no database") {
		t.Errorf("revoke: error = %v", err)
	}
}

// Certificates from ACME and SCEP are in the list like all others, and
// can be revoked.
func TestCertificatesFromACMEAndSCEPAreListed(t *testing.T) {
	testCA := startTestCA(t, withSCEP)

	address := freeAddress(t)
	testCA.acme.set(address)
	acmeOpts := acmeOptions{names: []string{"acme.example.com"}, outDir: t.TempDir(), httpAddress: address}
	if err := runACME(context.Background(), io.Discard, testCA.acmeConn(), acmeOpts); err != nil {
		t.Fatal(err)
	}
	scepConn := testCA.connection(t, "tls-client", "scep.example.com")
	if err := runSCEP(context.Background(), io.Discard, scepConn, scepOptions{names: []string{"scep.example.com"}, outDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runListCertificates(context.Background(), &out, testCA.cfg, false, "text"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"acme.example.com", "scep.example.com", "SCEP RA"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the list lacks %q:\n%s", want, out.String())
		}
	}
}
