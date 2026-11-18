// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"net"
	"strings"
)

// ACME holds which host names ACME clients may get certificates for.
// Create one with NewACME.
//
// With ACME a client proves that it controls a host name. That alone is
// not enough for this CA: the name must also be in one of the domains
// the administrator listed. So a client that controls some machine
// cannot get a certificate for a name the CA has no business with.
type ACME struct {
	domains []string     // lower case
	ranges  []*net.IPNet // IP addresses ACME may issue for
}

// NewACME builds the rules from the configured list of allowed domains.
func NewACME(allowedDomains []string) *ACME {
	a := &ACME{}
	for _, domain := range allowedDomains {
		a.domains = append(a.domains, strings.ToLower(domain))
	}
	return a
}

// WithIPRanges returns the rules with IP address ranges ACME clients may
// get certificates for (RFC 8738). Without them, no IP address.
func (a *ACME) WithIPRanges(ranges []*net.IPNet) *ACME {
	a.ranges = ranges
	return a
}

// CheckIP returns ErrNotAllowed if an ACME client may not have a
// certificate for the IP address.
func (a *ACME) CheckIP(ip net.IP) error {
	for _, r := range a.ranges {
		if r.Contains(ip) {
			return nil
		}
	}
	return fmt.Errorf("%w: the IP address %s is not in a range this CA issues certificates for", ErrNotAllowed, ip)
}

// CheckDomain returns ErrNotAllowed if an ACME client may not have a
// certificate for name.
//
// A name is allowed if it is one of the allowed domains or lies below
// one: "example.com" allows "example.com" and "web.example.com", but not
// "badexample.com". A wildcard is allowed as the whole first label, for a
// name that is itself allowed: "*.example.com", "*.web.example.com". (The
// ACME server proves wildcards with dns-01 only.) IP addresses are never
// allowed.
func (a *ACME) CheckDomain(name string) error {
	name = strings.ToLower(name)
	if base, ok := strings.CutPrefix(name, "*."); ok {
		if strings.Contains(base, "*") {
			return fmt.Errorf("%w: %q: a wildcard may only be the first label", ErrNotAllowed, name)
		}
		return a.CheckDomain(base)
	}
	if strings.Contains(name, "*") {
		return fmt.Errorf("%w: %q: a wildcard must be the whole first label, as in *.example.com", ErrNotAllowed, name)
	}
	if net.ParseIP(name) != nil {
		return fmt.Errorf("%w: IP addresses such as %q", ErrNotAllowed, name)
	}
	if !validHostName(name) {
		return fmt.Errorf("%w: %q is not a host name", ErrNotAllowed, name)
	}
	for _, domain := range a.domains {
		if name == domain || strings.HasSuffix(name, "."+domain) {
			return nil
		}
	}
	return fmt.Errorf("%w: the name %q is not in a domain this CA issues certificates for", ErrNotAllowed, name)
}

// validHostName reports whether name looks like a DNS host name: labels
// of letters, digits and hyphens, separated by dots.
func validHostName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			isLetterOrDigit := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
			if !isLetterOrDigit && c != '-' {
				return false
			}
		}
	}
	return true
}
