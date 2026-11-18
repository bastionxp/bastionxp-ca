// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"strings"
	"testing"
	"time"
)

func newLeafKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// A tls-server certificate verifies for its names against the root as a
// server certificate, is not a CA, and carries the CA's organization.
func TestIssueTLSServer(t *testing.T) {
	authority := newTestCA(t)
	key := newLeafKey(t)

	cert, err := authority.IssueX509(X509Request{
		Template:    TLSServer,
		PublicKey:   key.Public(),
		DNSNames:    []string{"web.example.com"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
	})
	if err != nil {
		t.Fatal(err)
	}

	verifyChain(t, authority, cert, x509.VerifyOptions{
		DNSName:   "web.example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if cert.IsCA {
		t.Error("leaf certificate must not be a CA")
	}
	if got := cert.Subject.Organization; len(got) != 1 || got[0] != "Test Org" {
		t.Errorf("organization = %v, want [Test Org]", got)
	}
	if got := cert.NotAfter.Sub(cert.NotBefore); got != TLSServer.DefaultValidity+backdate {
		t.Errorf("lifetime = %s, want the template default", got)
	}

	// A server certificate must not be usable as a client certificate.
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(authority.RootCert())
	intermediates.AddCert(authority.IntermediateCert())
	_, err = cert.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err == nil {
		t.Error("server certificate verified for client authentication")
	}
}

// A tls-client certificate verifies for client authentication, with the
// common name and email address asked for and the lifetime asked for.
func TestIssueTLSClient(t *testing.T) {
	authority := newTestCA(t)

	cert, err := authority.IssueX509(X509Request{
		Template:       TLSClient,
		PublicKey:      newLeafKey(t).Public(),
		CommonName:     "alice",
		EmailAddresses: []string{"alice@example.com"},
		Validity:       time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyChain(t, authority, cert, x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if cert.Subject.CommonName != "alice" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	if got := cert.NotAfter.Sub(cert.NotBefore); got != time.Hour+backdate {
		t.Errorf("lifetime = %s, want 1h plus backdate", got)
	}
}

// Two certificates never share a serial number.
func TestIssueX509SerialsAreUnique(t *testing.T) {
	authority := newTestCA(t)
	req := X509Request{Template: TLSClient, PublicKey: newLeafKey(t).Public(), CommonName: "alice"}

	first, err := authority.IssueX509(req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := authority.IssueX509(req)
	if err != nil {
		t.Fatal(err)
	}
	if first.SerialNumber.Cmp(second.SerialNumber) == 0 {
		t.Error("two certificates got the same serial number")
	}
}

// A certificate issued shortly before the intermediate expires ends when the
// intermediate does, not later.
func TestIssueX509NeverOutlivesTheCA(t *testing.T) {
	authority := newTestCA(t)
	// Pretend it is one day before the intermediate expires.
	expiry := authority.IntermediateCert().NotAfter
	authority.now = func() time.Time { return expiry.Add(-24 * time.Hour) }

	cert, err := authority.IssueX509(X509Request{
		Template:  TLSServer,
		PublicKey: newLeafKey(t).Public(),
		DNSNames:  []string{"web.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cert.NotAfter.After(expiry) {
		t.Errorf("certificate expires %s, after the CA at %s", cert.NotAfter, expiry)
	}
}

// Requests the profile does not allow are refused: a server certificate
// without a host name, a client certificate without any name, weak keys, and
// the other cases in the table.
func TestIssueX509Rejects(t *testing.T) {
	authority := newTestCA(t)
	goodKey := newLeafKey(t).Public()

	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		req     X509Request
		wantErr string
	}{
		{
			name:    "server without host name",
			req:     X509Request{Template: TLSServer, PublicKey: goodKey, CommonName: "web"},
			wantErr: "DNS name or IP address is required",
		},
		{
			name:    "client without any name",
			req:     X509Request{Template: TLSClient, PublicKey: goodKey},
			wantErr: "is required",
		},
		{
			name:    "validity above maximum",
			req:     X509Request{Template: TLSClient, PublicKey: goodKey, CommonName: "a", Validity: TLSClient.MaxValidity + time.Second},
			wantErr: "above the maximum",
		},
		{
			name:    "negative validity",
			req:     X509Request{Template: TLSClient, PublicKey: goodKey, CommonName: "a", Validity: -time.Hour},
			wantErr: "must be positive",
		},
		{
			name:    "weak RSA key",
			req:     X509Request{Template: TLSClient, PublicKey: weakRSA.Public(), CommonName: "a"},
			wantErr: "minimum is 2048",
		},
		{
			name:    "no public key",
			req:     X509Request{Template: TLSClient, CommonName: "a"},
			wantErr: "no public key",
		},
		{
			name:    "no profile",
			req:     X509Request{PublicKey: goodKey, CommonName: "a"},
			wantErr: "no profile",
		},
		{
			name:    "empty DNS name",
			req:     X509Request{Template: TLSServer, PublicKey: goodKey, DNSNames: []string{""}},
			wantErr: "empty DNS name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := authority.IssueX509(tt.req)
			if err == nil {
				t.Fatal("expected an error, got a certificate")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// A request built from a CSR carries the CSR's names, and the certificate
// issued for it has them.
func TestRequestFromCSR(t *testing.T) {
	authority := newTestCA(t)
	key := newLeafKey(t)

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "web.example.com"},
		DNSNames: []string{"web.example.com", "www.example.com"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}

	req, err := RequestFromCSR(TLSServer, csr)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := authority.IssueX509(req)
	if err != nil {
		t.Fatal(err)
	}
	verifyChain(t, authority, cert, x509.VerifyOptions{DNSName: "www.example.com"})
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Error("certificate is not for the CSR's key")
	}

	// A CSR whose content was changed after signing must be rejected.
	csr.Signature[len(csr.Signature)-1] ^= 0xff
	if _, err := RequestFromCSR(TLSServer, csr); err == nil {
		t.Error("RequestFromCSR accepted a CSR with a bad signature")
	}
}

// The TLS profiles are found by name, and an SSH profile is not found as a
// TLS one.
func TestX509TemplateByName(t *testing.T) {
	for _, want := range []X509Template{TLSServer, TLSClient} {
		got, ok := X509TemplateByName(want.Name)
		if !ok || got.Name != want.Name {
			t.Errorf("X509TemplateByName(%q) = %q, %v", want.Name, got.Name, ok)
		}
	}
	if _, ok := X509TemplateByName("ssh-user"); ok {
		t.Error("ssh-user must not be found as an X.509 template")
	}
}
