// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/scep"
)

const staticPassword = "a-long-shared-scep-password"

// enrollCSR sends a CSR built from template, with the challenge.
func (e *scepEnv) enrollCSR(t *testing.T, template *x509.CertificateRequest, challenge string) (*x509.Certificate, error) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := scep.NewCSR(template, key, challenge)
	if err != nil {
		t.Fatal(err)
	}
	return e.device.Enroll(context.Background(), csr, key, e.caCerts)
}

func staticEnv(t *testing.T, change func(*SCEPStatic)) *scepEnv {
	t.Helper()
	static := &SCEPStatic{Challenge: staticPassword, Template: "tls-client",
		DNSDomains: []string{"devices.example.com"}, EmailDomains: []string{"example.com"}, MaxPerHour: 100}
	if change != nil {
		change(static)
	}
	return newSCEPEnvWith(t, static)
}

// SCEP with a static password, for device management systems: a device known
// only by its serial number gets a client certificate; names in the allowed
// domains are issued; DNS names elsewhere, look-alike domains, wildcards, IP
// addresses and email addresses outside the allowed domains are refused.
func TestSCEPStaticChallenge(t *testing.T) {
	env := staticEnv(t, nil)

	// A device known by its serial number: only a common name.
	cert, err := env.enrollCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "C02XK1ABCDE"}}, staticPassword)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "C02XK1ABCDE" || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("CN %q, usage %v", cert.Subject.CommonName, cert.ExtKeyUsage)
	}
	// Names in the allowed domains.
	if _, err := env.enrollCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "laptop-1"},
		DNSNames: []string{"laptop-1.devices.example.com"}, EmailAddresses: []string{"alice@example.com"}}, staticPassword); err != nil {
		t.Errorf("names in the allowed domains: %v", err)
	}

	refused := map[string]*x509.CertificateRequest{
		"DNS name elsewhere":   {Subject: pkix.Name{CommonName: "x"}, DNSNames: []string{"web.example.com"}},
		"look-alike domain":    {Subject: pkix.Name{CommonName: "x"}, DNSNames: []string{"evildevices.example.com"}},
		"wildcard":             {Subject: pkix.Name{CommonName: "x"}, DNSNames: []string{"*.devices.example.com"}},
		"IP address":           {Subject: pkix.Name{CommonName: "x"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.5")}},
		"email elsewhere":      {Subject: pkix.Name{CommonName: "x"}, EmailAddresses: []string{"mallory@evil.net"}},
		"email in a subdomain": {Subject: pkix.Name{CommonName: "x"}, EmailAddresses: []string{"bob@sub.evil.example.org"}},
	}
	for name, template := range refused {
		t.Run(name, func(t *testing.T) {
			if _, err := env.enrollCSR(t, template, staticPassword); err == nil {
				t.Error("issued")
			}
		})
	}
}

// Tokens keep working next to the password; anything else is refused.
func TestSCEPStaticAndTokens(t *testing.T) {
	env := staticEnv(t, nil)
	tok := env.issueToken(t, "tls-client", "printer.example.com")
	if _, _, err := env.enroll(t, tok, "printer.example.com"); err != nil {
		t.Errorf("token: %v", err)
	}
	for _, wrong := range []string{"a-long-shared-scep-passworD", staticPassword + " ", "not-it"} {
		if _, err := env.enrollCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, wrong); err == nil {
			t.Errorf("%q: issued", wrong)
		}
	}
}

// Enrollments with the static password are limited per hour; tokens are not
// counted against that limit.
func TestSCEPStaticLimit(t *testing.T) {
	env := staticEnv(t, func(s *SCEPStatic) { s.MaxPerHour = 2 })
	csr := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device"}}
	for i := range 2 {
		if _, err := env.enrollCSR(t, csr, staticPassword); err != nil {
			t.Fatalf("enrollment %d: %v", i+1, err)
		}
	}
	if _, err := env.enrollCSR(t, csr, staticPassword); err == nil {
		t.Error("third enrollment: issued over the limit")
	}
	// A token is not counted against the password's limit.
	tok := env.issueToken(t, "tls-client", "printer.example.com")
	if _, _, err := env.enroll(t, tok, "printer.example.com"); err != nil {
		t.Errorf("token after the limit: %v", err)
	}
}

// The static password can issue with another profile, here TLS server
// certificates.
func TestSCEPStaticServerTemplate(t *testing.T) {
	env := staticEnv(t, func(s *SCEPStatic) { s.Template = "tls-server" })
	cert, err := env.enrollCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "router-1.devices.example.com"},
		DNSNames: []string{"router-1.devices.example.com"}}, staticPassword)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("usage %v, want server auth", cert.ExtKeyUsage)
	}
}
