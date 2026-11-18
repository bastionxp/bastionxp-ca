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
	"encoding/asn1"
	"net"
	"slices"
	"testing"
)

func profile(t *testing.T, base, name string, change func(*X509Template)) X509Template {
	t.Helper()
	p, ok := ProfileBase(base, name)
	if !ok {
		t.Fatalf("no base %s", base)
	}
	if change != nil {
		change(&p)
	}
	return p
}

// A custom profile's organizational unit, policies, custom extension, key
// usage and extended key usage are in the certificate.
func TestProfileInTheCertificate(t *testing.T) {
	authority := newTestCA(t)
	policy := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}
	extID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 2}
	deviceClient := profile(t, "tls-client", "device-client", func(p *X509Template) {
		p.OrganizationalUnit = []string{"Devices"}
		p.Policies = []asn1.ObjectIdentifier{policy}
		p.Extensions = []pkix.Extension{{Id: extID, Value: []byte{0x0c, 0x01, 'x'}}}
		p.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
		p.Names = &NamePolicy{Email: true}
	})
	authority.SetProfiles([]X509Template{deviceClient}, nil)
	got, ok := authority.X509Template("device-client")
	if !ok {
		t.Fatal("profile not found by name")
	}
	cert, err := authority.IssueX509(X509Request{Template: got, PublicKey: newLeafKey(t).Public(),
		CommonName: "laptop-1", EmailAddresses: []string{"alice@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cert.Subject.OrganizationalUnit, []string{"Devices"}) {
		t.Errorf("OU %v", cert.Subject.OrganizationalUnit)
	}
	if len(cert.Policies) != 1 || cert.Policies[0].String() != policy.String() {
		t.Errorf("policies %v", cert.Policies)
	}
	if !slices.ContainsFunc(cert.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(extID) }) {
		t.Error("the custom extension is missing")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyAgreement {
		t.Errorf("key usage %v", cert.KeyUsage)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ext key usage %v", cert.ExtKeyUsage)
	}
}

// A custom profile's rules refuse names it does not allow (DNS names, IP
// addresses, wildcards), small RSA keys and other curves, a missing common
// name, and host names on code signing; the built-in profiles are
// unaffected, and an unknown profile is not found.
func TestProfileRules(t *testing.T) {
	authority := newTestCA(t)
	ec := newLeafKey(t).Public()
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	emailOnly := profile(t, "tls-client", "p", func(p *X509Template) { p.Names = &NamePolicy{Email: true} })
	noWildcard := profile(t, "tls-server", "p", func(p *X509Template) { p.Names = &NamePolicy{DNS: true} })
	strictKeys := profile(t, "tls-client", "p", func(p *X509Template) {
		p.Keys = &KeyPolicy{Algorithms: []string{"rsa", "ecdsa"}, MinRSABits: 3072, Curves: []string{"P-256"}}
	})
	codeSigning := profile(t, "code-signing", "p", nil)

	refused := map[string]X509Request{
		"DNS name":       {Template: emailOnly, PublicKey: ec, CommonName: "x", DNSNames: []string{"web.example.com"}},
		"IP address":     {Template: emailOnly, PublicKey: ec, CommonName: "x", IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}},
		"wildcard":       {Template: noWildcard, PublicKey: ec, DNSNames: []string{"*.example.com"}},
		"small RSA":      {Template: strictKeys, PublicKey: &rsa2048.PublicKey, CommonName: "x"},
		"curve":          {Template: strictKeys, PublicKey: &p384.PublicKey, CommonName: "x"},
		"no common name": {Template: codeSigning, PublicKey: ec, EmailAddresses: []string{}},
		"code names":     {Template: codeSigning, PublicKey: ec, CommonName: "Signer", DNSNames: []string{"x.example.com"}},
	}
	for name, req := range refused {
		t.Run(name, func(t *testing.T) {
			if _, err := authority.IssueX509(req); err == nil {
				t.Error("issued")
			}
		})
	}
	cert, err := authority.IssueX509(X509Request{Template: codeSigning, PublicKey: ec, CommonName: "Release Signer"})
	if err != nil {
		t.Fatal(err)
	}
	if cert.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning {
		t.Errorf("code signing: %v", cert.ExtKeyUsage)
	}
	// The built-in templates are unaffected.
	if _, err := authority.IssueX509(X509Request{Template: TLSServer, PublicKey: ec, DNSNames: []string{"*.example.com"}}); err != nil {
		t.Errorf("built-in tls-server with a wildcard: %v", err)
	}
	if _, ok := authority.X509Template("device-client"); ok {
		t.Error("a profile that was never set is found")
	}
}
