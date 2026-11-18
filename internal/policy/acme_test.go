// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// Which names ACME may issue for: the allowed domains and their subdomains,
// in any case, punycode and single-level wildcards; not other or look-alike
// domains, bare suffixes, other wildcard forms, IP addresses, trailing or
// empty dots, bad hyphens, underscores, spaces, paths, ports, email
// addresses or labels too long.
func TestACMECheckDomain(t *testing.T) {
	a := NewACME([]string{"Example.com", "corp.internal"})

	allowed := []string{
		"example.com",
		"web.example.com",
		"a.b.c.example.com",
		"WEB.Example.COM",
		"my-host.corp.internal",
		"corp.internal",
		"xn--bcher-kva.example.com",
		"*.example.com",
		"*.web.example.com",
		"*.corp.internal",
	}
	for _, name := range allowed {
		if err := a.CheckDomain(name); err != nil {
			t.Errorf("%q: unexpected error: %v", name, err)
		}
	}

	refused := []string{
		"",
		"other.com",
		"badexample.com",           // ends with the text, but is another domain
		"example.com.attacker.net", // starts with it
		"com",
		"internal",
		"*",
		"*.",
		"*.other.com",
		"*.com",
		"**.example.com",
		"*.*.example.com",
		"web.*.example.com",
		"*web.example.com",
		"10.0.0.5",
		"::1",
		"web.example.com.", // trailing dot
		".example.com",
		"web..example.com",
		"-web.example.com",
		"web-.example.com",
		"web_1.example.com",
		"web example.com",
		"web.example.com/path",
		"web.example.com:8080",
		"user@example.com",
		strings.Repeat("a", 64) + ".example.com", // label too long
	}
	for _, name := range refused {
		if err := a.CheckDomain(name); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%q: error = %v, want ErrNotAllowed", name, err)
		}
	}
}

// With no domains configured, ACME may issue for no name.
func TestACMEWithNoDomainsAllowsNothing(t *testing.T) {
	a := NewACME(nil)
	if err := a.CheckDomain("example.com"); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("error = %v, want ErrNotAllowed", err)
	}
}

// ACME may issue for IP addresses only in the configured ranges, and for
// none without ranges.
func TestACMECheckIP(t *testing.T) {
	_, ten, _ := net.ParseCIDR("10.0.0.0/8")
	_, ula, _ := net.ParseCIDR("fd00::/8")
	a := NewACME([]string{"example.com"}).WithIPRanges([]*net.IPNet{ten, ula})
	for ip, want := range map[string]bool{"10.1.2.3": true, "11.0.0.1": false, "fd00::5": true, "::1": false, "192.168.0.1": false} {
		if err := a.CheckIP(net.ParseIP(ip)); (err == nil) != want {
			t.Errorf("%s: error = %v, want allowed %v", ip, err, want)
		}
	}
	if err := NewACME([]string{"example.com"}).CheckIP(net.ParseIP("10.0.0.1")); !errors.Is(err, ErrNotAllowed) {
		t.Error("an IP address was allowed without ranges")
	}
}
