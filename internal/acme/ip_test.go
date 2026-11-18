// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"

	acmeclient "golang.org/x/crypto/acme"

	"github.com/bastionxp/bastionxp-ca/internal/policy"
)

// ipEnv allows 10.0.0.0/8 and fd00::/8 besides example.com.
func ipEnv(t *testing.T) *testEnv {
	t.Helper()
	env := newTestEnv(t)
	_, v4, _ := net.ParseCIDR("10.0.0.0/8")
	_, v6, _ := net.ParseCIDR("fd00::/8")
	env.server.SetRules(policy.NewACME([]string{"example.com"}).WithIPRanges([]*net.IPNet{v4, v6}))
	return env
}

// ipCSR is a CSR with IP addresses as subject alternative names.
func ipCSR(t *testing.T, ips ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{}
	for _, ip := range ips {
		template.IPAddresses = append(template.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// An IPv4 and an IPv6 address proved with http-01 (RFC 8738): ip
// identifiers, no dns-01 offered, and a certificate with the addresses as IP
// addresses, not DNS names.
func TestIPAddressWithHTTP01(t *testing.T) {
	env := ipEnv(t)
	client := env.registered()
	ctx := context.Background()
	order, err := client.AuthorizeOrder(ctx, acmeclient.IPIDs("10.0.0.5", "fd00::5"))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		if authz.Identifier.Type != "ip" {
			t.Errorf("identifier type %q, want ip", authz.Identifier.Type)
		}
		// RFC 8738: no dns-01 for an IP address.
		if got := challengeTypes(authz); !slices.Equal(got, []string{"http-01", "tls-alpn-01"}) {
			t.Errorf("challenges %v", got)
		}
		challenge := http01Challenge(t, authz)
		answer, _ := client.HTTP01ChallengeResponse(challenge.Token)
		host := authz.Identifier.Value
		if net.ParseIP(host).To4() == nil {
			host = "[" + host + "]"
		}
		env.hosts.serve(host, client.HTTP01ChallengePath(challenge.Token), answer)
		if _, err := client.Accept(ctx, challenge); err != nil {
			t.Fatal(err)
		}
		if _, err := client.WaitAuthorization(ctx, u); err != nil {
			t.Fatalf("%s: %v", authz.Identifier.Value, err)
		}
	}
	ready, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		t.Fatal(err)
	}
	der, _, err := client.CreateOrderCert(ctx, ready.FinalizeURL, ipCSR(t, "10.0.0.5", "fd00::5"), false)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.IPAddresses) != 2 || len(cert.DNSNames) != 0 {
		t.Errorf("certificate: IPs %v, DNS names %v", cert.IPAddresses, cert.DNSNames)
	}
}

// ipALPNCert is the tls-alpn-01 certificate for an IP address (RFC 8738).
func ipALPNCert(t *testing.T, ip, keyAuth string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sum := sha256.Sum256([]byte(keyAuth))
	value, _ := asn1.Marshal(sum[:])
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "challenge"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		IPAddresses:     []net.IP{net.ParseIP(ip)},
		ExtraExtensions: []pkix.Extension{{Id: idPeAcmeIdentifier, Critical: true, Value: value}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// An IP address proved with tls-alpn-01, the CA asking for its reverse name
// (RFC 8738).
func TestIPAddressWithTLSALPN01(t *testing.T) {
	env := ipEnv(t)
	client := env.registered()
	ctx := context.Background()
	o, err := client.AuthorizeOrder(ctx, acmeclient.IPIDs("10.0.0.5"))
	if err != nil {
		t.Fatal(err)
	}
	authz, err := client.GetAuthorization(ctx, o.AuthzURLs[0])
	if err != nil {
		t.Fatal(err)
	}
	challenge := challengeOfType(t, authz, "tls-alpn-01")
	keyAuth, _ := client.HTTP01ChallengeResponse(challenge.Token)
	// The CA asks for the reverse name; the fake answers only that.
	env.hosts.tls.set("5.0.0.10.in-addr.arpa", ipALPNCert(t, "10.0.0.5", keyAuth), true)
	if _, err := client.Accept(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WaitAuthorization(ctx, o.AuthzURLs[0]); err != nil {
		t.Fatal(err)
	}
}

// The reverse names of IPv4 and IPv6 addresses, for tls-alpn-01.
func TestReverseName(t *testing.T) {
	for ip, want := range map[string]string{
		"10.0.0.5":    "5.0.0.10.in-addr.arpa",
		"2001:db8::1": "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
	} {
		if got := reverseName(net.ParseIP(ip)); got != want {
			t.Errorf("%s: %s, want %s", ip, got, want)
		}
	}
}

// An IP address outside the configured ranges is refused, and text that is
// not one is malformed; the CSR must carry the ordered address as an IP
// address.
func TestIPAddressRefusals(t *testing.T) {
	env := ipEnv(t)
	client := env.registered()
	ctx := context.Background()
	// Outside the ranges.
	_, err := client.AuthorizeOrder(ctx, acmeclient.IPIDs("192.168.1.1"))
	wantProblem(t, err, "rejectedIdentifier")
	// Not an IP address.
	_, err = client.AuthorizeOrder(ctx, []acmeclient.AuthzID{{Type: "ip", Value: "web.example.com"}})
	wantProblem(t, err, "malformed")
	// The CSR must carry it as an IP address, not as a DNS name.
	if err := checkCSRNames(&x509.CertificateRequest{DNSNames: []string{"10.0.0.5"}}, []string{"10.0.0.5"}); err == nil {
		t.Error("an IP address as a DNS name was accepted")
	}
	if err := checkCSRNames(&x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("10.0.0.6")}}, []string{"10.0.0.5"}); err == nil {
		t.Error("another IP address was accepted")
	}
}
