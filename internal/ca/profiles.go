// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"
	"strings"
)

// Profiles are X.509 templates an administrator defines, beside the
// built-in ones: their own lifetimes, key usages, subject, allowed kinds
// of names, certificate policies, extensions and key rules. The CA
// enforces them in IssueX509, so they hold whichever way a request
// arrives.

// NamePolicy says which kinds of names a certificate may contain.
type NamePolicy struct {
	DNS, IP, Email bool
	// Wildcard allows DNS names such as *.example.com (needs DNS).
	Wildcard bool
}

// KeyPolicy limits the keys certificates may be for.
type KeyPolicy struct {
	// Algorithms are "ecdsa", "rsa", "ed25519"; empty: all three.
	Algorithms []string
	// MinRSABits is the smallest RSA key; 0: the CA's minimum (2048).
	MinRSABits int
	// Curves are "P-256", "P-384", "P-521"; empty: all three.
	Curves []string
}

// Bases a profile starts from: what it gets unless it says otherwise.
var profileBases = map[string]X509Template{
	TLSServer.Name: TLSServer,
	TLSClient.Name: TLSClient,
	"email": {
		Base:            "email",
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		DefaultValidity: 365 * day,
		MaxValidity:     3 * 365 * day,
		Names:           &NamePolicy{Email: true},
	},
	"code-signing": {
		Base:              "code-signing",
		ExtKeyUsage:       []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		DefaultValidity:   365 * day,
		MaxValidity:       3 * 365 * day,
		RequireCommonName: true,
		Names:             &NamePolicy{},
	},
}

// ProfileBases returns the names of the bases a profile can start from.
func ProfileBases() []string {
	names := make([]string, 0, len(profileBases))
	for name := range profileBases {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// ProfileBase returns a copy of a base, named name.
func ProfileBase(base, name string) (X509Template, bool) {
	t, ok := profileBases[base]
	if !ok {
		return X509Template{}, false
	}
	t.Name = name
	t.ExtKeyUsage = slices.Clone(t.ExtKeyUsage)
	if t.Names != nil {
		names := *t.Names
		t.Names = &names
	}
	return t, true
}

// SetProfiles gives the CA its profiles, X.509 and SSH. Call it once,
// before the CA is used by several goroutines.
func (c *CA) SetProfiles(profiles []X509Template, sshProfiles []SSHTemplate) {
	c.profiles = make(map[string]X509Template, len(profiles))
	for _, p := range profiles {
		c.profiles[p.Name] = p
	}
	c.sshProfiles = make(map[string]SSHTemplate, len(sshProfiles))
	for _, p := range sshProfiles {
		c.sshProfiles[p.Name] = p
	}
}

// SSHTemplate returns the SSH template with that name: a profile, or a
// built-in template.
func (c *CA) SSHTemplate(name string) (SSHTemplate, bool) {
	if p, ok := c.sshProfiles[name]; ok {
		return p, true
	}
	return SSHTemplateByName(name)
}

// SSHProfileBase returns a copy of the built-in SSH template base, named
// name, for a profile to start from.
func SSHProfileBase(base, name string) (SSHTemplate, bool) {
	t, ok := SSHTemplateByName(base)
	if !ok {
		return SSHTemplate{}, false
	}
	t.Name = name
	t.Extensions = copyMap(t.Extensions)
	t.CriticalOptions = copyMap(t.CriticalOptions)
	return t, true
}

// SSHUserExtensions are the extensions an SSH user certificate may carry
// (OpenSSH PROTOCOL.certkeys).
var SSHUserExtensions = []string{
	"no-touch-required", "permit-X11-forwarding", "permit-agent-forwarding",
	"permit-port-forwarding", "permit-pty", "permit-user-rc",
}

// SSHCriticalOptions are the critical options an SSH user certificate may
// carry (OpenSSH PROTOCOL.certkeys).
var SSHCriticalOptions = []string{"force-command", "source-address", "verify-required"}

// X509Template returns the template with that name: a profile, or a
// built-in template.
func (c *CA) X509Template(name string) (X509Template, bool) {
	if p, ok := c.profiles[name]; ok {
		return p, true
	}
	return X509TemplateByName(name)
}

// checkProfile applies a template's limits on names and keys.
func checkProfile(req X509Request) error {
	t := req.Template
	if t.RequireCommonName && req.CommonName == "" {
		return fmt.Errorf("a common name is required")
	}
	if n := t.Names; n != nil {
		switch {
		case !n.DNS && len(req.DNSNames) > 0:
			return fmt.Errorf("DNS names are not allowed")
		case !n.IP && len(req.IPAddresses) > 0:
			return fmt.Errorf("IP addresses are not allowed")
		case !n.Email && len(req.EmailAddresses) > 0:
			return fmt.Errorf("email addresses are not allowed")
		}
		if !n.Wildcard {
			for _, name := range req.DNSNames {
				if strings.Contains(name, "*") {
					return fmt.Errorf("wildcard names such as %q are not allowed", name)
				}
			}
		}
	}
	if t.Keys != nil {
		return t.Keys.check(req.PublicKey)
	}
	return nil
}

func (k *KeyPolicy) check(pub crypto.PublicKey) error {
	var algorithm string
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		algorithm = "ecdsa"
		if len(k.Curves) > 0 && !slices.Contains(k.Curves, key.Curve.Params().Name) {
			return fmt.Errorf("the curve %s is not allowed: use %s", key.Curve.Params().Name, strings.Join(k.Curves, ", "))
		}
	case *rsa.PublicKey:
		algorithm = "rsa"
		if bits := key.N.BitLen(); bits < k.MinRSABits {
			return fmt.Errorf("the RSA key has %d bits, at least %d are required", bits, k.MinRSABits)
		}
	case ed25519.PublicKey:
		algorithm = "ed25519"
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
	if len(k.Algorithms) > 0 && !slices.Contains(k.Algorithms, algorithm) {
		return fmt.Errorf("%s keys are not allowed: use %s", algorithm, strings.Join(k.Algorithms, ", "))
	}
	return nil
}

// policyOIDs converts policy OIDs to the form CreateCertificate writes.
func policyOIDs(oids []asn1.ObjectIdentifier) []x509.OID {
	var out []x509.OID
	for _, oid := range oids {
		ints := make([]uint64, len(oid))
		for i, n := range oid {
			ints[i] = uint64(n)
		}
		if o, err := x509.OIDFromInts(ints); err == nil {
			out = append(out, o)
		}
	}
	return out
}
