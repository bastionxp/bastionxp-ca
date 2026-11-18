// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"fmt"
	"net"
	"slices"
	"strings"
)

// NameConstraints limit which names the intermediate can sign for (RFC
// 5280, section 4.2.1.10). They are written into the intermediate
// certificate, and every TLS client checks them. So even if the
// intermediate key were stolen, certificates for other names would be
// refused by everybody.
//
// When any constraint is set, a kind of name that is not listed is not
// allowed at all: with only DNS domains given, no IP address and no email
// address is allowed, rather than every one.
type NameConstraints struct {
	DNSDomains   []string     // "example.com" allows it and every name below it
	IPRanges     []*net.IPNet // e.g. 10.0.0.0/8
	EmailDomains []string     // "example.com" allows addresses at example.com; ".example.com" those below it
}

// noneDomain is a domain no certificate can have (RFC 2606). Permitting
// only it forbids a kind of name.
const noneDomain = "invalid"

// IsZero reports whether no constraint is set.
func (n NameConstraints) IsZero() bool {
	return len(n.DNSDomains) == 0 && len(n.IPRanges) == 0 && len(n.EmailDomains) == 0
}

// apply writes the constraints into a CA certificate template.
func (n NameConstraints) apply(t *x509.Certificate) {
	if n.IsZero() {
		return
	}
	t.PermittedDNSDomainsCritical = true // RFC 5280: MUST be critical
	t.PermittedDNSDomains = orNone(n.DNSDomains)
	t.PermittedEmailAddresses = orNone(n.EmailDomains)
	t.PermittedURIDomains = []string{noneDomain} // BastionXP CA never issues URIs
	if len(n.IPRanges) > 0 {
		t.PermittedIPRanges = n.IPRanges
	} else {
		t.ExcludedIPRanges = []*net.IPNet{
			{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		}
	}
}

func orNone(list []string) []string {
	if len(list) == 0 {
		return []string{noneDomain}
	}
	return list
}

// Permits reports whether the constraints allow a name: a DNS name, an IP
// address or an email address. No constraints allow everything.
func (n NameConstraints) Permits(name string) bool {
	if n.IsZero() {
		return true
	}
	if ip := net.ParseIP(name); ip != nil {
		return slices.ContainsFunc(n.IPRanges, func(r *net.IPNet) bool { return r.Contains(ip) })
	}
	if _, domain, ok := strings.Cut(name, "@"); ok {
		domain = strings.ToLower(domain)
		return slices.ContainsFunc(n.EmailDomains, func(c string) bool {
			c = strings.ToLower(c)
			if strings.HasPrefix(c, ".") {
				return strings.HasSuffix(domain, c)
			}
			return domain == c
		})
	}
	name = strings.ToLower(strings.TrimPrefix(name, "*."))
	return slices.ContainsFunc(n.DNSDomains, func(c string) bool {
		c = strings.ToLower(c)
		if strings.HasPrefix(c, ".") {
			return strings.HasSuffix(name, c)
		}
		return name == c || strings.HasSuffix(name, "."+c)
	})
}

// constrained reports whether the intermediate carries name constraints.
func (c *CA) constrained() bool {
	i := c.intermediateCert
	return len(i.PermittedDNSDomains)+len(i.ExcludedDNSDomains)+len(i.PermittedIPRanges)+len(i.ExcludedIPRanges)+
		len(i.PermittedEmailAddresses)+len(i.ExcludedEmailAddresses)+len(i.PermittedURIDomains)+len(i.ExcludedURIDomains) > 0
}

// checkConstraints verifies a new certificate the way clients will: a
// certificate they would refuse is not handed out.
func (c *CA) checkConstraints(cert *x509.Certificate) error {
	if !c.constrained() {
		return nil
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.rootCert)
	intermediates := x509.NewCertPool()
	for _, i := range c.Chain() {
		intermediates.AddCert(i)
	}
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   c.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("a name is outside the CA's name constraints: %w", err)
	}
	return nil
}
