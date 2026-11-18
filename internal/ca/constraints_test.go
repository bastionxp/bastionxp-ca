// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"net"
	"strings"
	"testing"
)

func constrainedCA(t *testing.T, n NameConstraints) *CA {
	t.Helper()
	dir := t.TempDir()
	opts := testOptions
	opts.NameConstraints = n
	if err := Init(dir, opts); err != nil {
		t.Fatal(err)
	}
	authority, err := Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// Name constraints go into the intermediate, critical: the allowed DNS
// domains and IP ranges, and no email addresses when none are listed; the
// root has none.
func TestNameConstraintsInTheIntermediate(t *testing.T) {
	authority := constrainedCA(t, NameConstraints{DNSDomains: []string{"example.com"}, IPRanges: []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}})
	i := authority.IntermediateCert()
	if !i.PermittedDNSDomainsCritical || len(i.PermittedDNSDomains) != 1 || i.PermittedDNSDomains[0] != "example.com" {
		t.Errorf("DNS constraints: critical %v, %v", i.PermittedDNSDomainsCritical, i.PermittedDNSDomains)
	}
	if len(i.PermittedIPRanges) != 1 || len(i.ExcludedIPRanges) != 0 {
		t.Errorf("IP constraints: permitted %v, excluded %v", i.PermittedIPRanges, i.ExcludedIPRanges)
	}
	// Not listed: not allowed at all.
	if len(i.PermittedEmailAddresses) != 1 || i.PermittedEmailAddresses[0] != noneDomain {
		t.Errorf("email constraints %v, want none allowed", i.PermittedEmailAddresses)
	}
	// The root has none: it is offline, and the intermediate is what signs.
	if r := authority.RootCert(); len(r.PermittedDNSDomains) != 0 {
		t.Error("the root has name constraints")
	}
}

// With name constraints, names inside them are issued and accepted by a
// client that has only the root; another domain, a look-alike, one bad name
// among good ones, and an email address are refused.
func TestIssueWithinNameConstraints(t *testing.T) {
	authority := constrainedCA(t, NameConstraints{DNSDomains: []string{"example.com"}, IPRanges: []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}})
	ok := X509Request{Template: TLSServer, PublicKey: newLeafKey(t).Public(),
		DNSNames: []string{"web.example.com", "example.com"}, IPAddresses: []net.IP{net.ParseIP("10.1.2.3")}}
	cert, err := authority.IssueX509(ok)
	if err != nil {
		t.Fatal(err)
	}
	// A client with only the root accepts it.
	verifyChain(t, authority, cert, x509.VerifyOptions{DNSName: "web.example.com"})

	refused := map[string]X509Request{
		"other domain": {Template: TLSServer, PublicKey: newLeafKey(t).Public(), DNSNames: []string{"web.other.com"}},
		"look-alike":   {Template: TLSServer, PublicKey: newLeafKey(t).Public(), DNSNames: []string{"badexample.com"}},
		"other IP":     {Template: TLSServer, PublicKey: newLeafKey(t).Public(), IPAddresses: []net.IP{net.ParseIP("192.168.1.1")}},
		"one bad name": {Template: TLSServer, PublicKey: newLeafKey(t).Public(), DNSNames: []string{"web.example.com", "evil.net"}},
		"email":        {Template: TLSClient, PublicKey: newLeafKey(t).Public(), CommonName: "alice", EmailAddresses: []string{"alice@example.com"}},
	}
	for name, req := range refused {
		t.Run(name, func(t *testing.T) {
			if _, err := authority.IssueX509(req); err == nil || !strings.Contains(err.Error(), "name constraints") {
				t.Errorf("error = %v, want a refusal for the name constraints", err)
			}
		})
	}
}

// With DNS domains only, no IP address is allowed: not every one.
func TestNameConstraintsDNSOnlyForbidsIPs(t *testing.T) {
	authority := constrainedCA(t, NameConstraints{DNSDomains: []string{"example.com"}})
	_, err := authority.IssueX509(X509Request{Template: TLSServer, PublicKey: newLeafKey(t).Public(),
		DNSNames: []string{"web.example.com"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.5")}})
	if err == nil {
		t.Error("an IP address was allowed")
	}
}

// Which names the constraints permit: a domain and its subdomains, or only
// subdomains with a leading dot, for DNS names and email addresses; no
// constraints allow everything.
func TestPermits(t *testing.T) {
	n := NameConstraints{
		DNSDomains:   []string{"example.com", ".corp.internal"},
		IPRanges:     []*net.IPNet{mustCIDR(t, "10.0.0.0/8"), mustCIDR(t, "fd00::/8")},
		EmailDomains: []string{"example.com", ".example.org"},
	}
	for name, want := range map[string]bool{
		"example.com": true, "web.example.com": true, "WEB.Example.com": true, "*.example.com": true,
		"badexample.com": false, "example.com.evil.net": false,
		"corp.internal": false, "host.corp.internal": true,
		"10.1.2.3": true, "11.0.0.1": false, "fd00::1": true, "::1": false,
		"alice@example.com": true, "alice@sub.example.com": false, "bob@team.example.org": true, "bob@example.org": false,
	} {
		if got := n.Permits(name); got != want {
			t.Errorf("Permits(%q) = %v, want %v", name, got, want)
		}
	}
	if !(NameConstraints{}).Permits("anything.at.all") {
		t.Error("no constraints must allow everything")
	}
}
