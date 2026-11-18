// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
)

// Profile is a certificate template of the administrator's own. It
// starts from a base and changes what it lists. An X.509 profile:
//
//	profiles:
//	  - name: device-client
//	    base: tls-client
//	    validity: 365d
//	    subject: { organizational_unit: [Devices] }
//	    names: { email: true }
//
// An SSH profile starts from ssh-user or ssh-host:
//
//   - name: ops-ssh
//     base: ssh-user
//     validity: 8h
//     ssh:
//     extensions: [permit-pty, permit-agent-forwarding]
//     critical_options: { source-address: 10.0.0.0/8 }
type Profile struct {
	// Name is what tokens, logins and SCEP refer to, e.g. "device-client".
	Name string `yaml:"name"`
	// Base is "tls-server", "tls-client", "email", "code-signing",
	// "ssh-user" or "ssh-host".
	Base string `yaml:"base"`
	// Validity is the default lifetime and MaxValidity the longest a
	// request may ask for: "365d", "8h", "90m".
	Validity    string `yaml:"validity"`
	MaxValidity string `yaml:"max_validity"`
	// KeyUsage replaces the base's: digital_signature, key_encipherment,
	// content_commitment, data_encipherment, key_agreement.
	KeyUsage []string `yaml:"key_usage"`
	// ExtKeyUsage replaces the base's: server_auth, client_auth,
	// email_protection, code_signing, time_stamping, ocsp_signing.
	ExtKeyUsage []string `yaml:"ext_key_usage"`
	Subject     struct {
		// OrganizationalUnit is written into every certificate's subject.
		OrganizationalUnit []string `yaml:"organizational_unit"`
		// RequireCommonName refuses requests without a common name.
		RequireCommonName bool `yaml:"require_common_name"`
	} `yaml:"subject"`
	// Names lists the kinds of names allowed; left out, the base's.
	Names *struct {
		DNS      bool `yaml:"dns"`
		IP       bool `yaml:"ip"`
		Email    bool `yaml:"email"`
		Wildcard bool `yaml:"wildcard"`
	} `yaml:"names"`
	// Policies are certificate policy OIDs, e.g. "1.3.6.1.4.1.55555.1".
	Policies []string `yaml:"policies"`
	// Extensions are added to every certificate as they are.
	Extensions []struct {
		OID      string `yaml:"oid"`
		Critical bool   `yaml:"critical"`
		// ValueHex is the extension's DER value, in hex.
		ValueHex string `yaml:"value_hex"`
	} `yaml:"extensions"`
	// Keys limits the keys certificates may be for.
	Keys *struct {
		Algorithms []string `yaml:"algorithms"` // ecdsa, rsa, ed25519
		MinRSABits int      `yaml:"min_rsa_bits"`
		Curves     []string `yaml:"curves"` // P-256, P-384, P-521
	} `yaml:"keys"`
	// SSH holds the settings of an SSH user profile.
	SSH *struct {
		// Extensions replace the base's: what a session may do, e.g.
		// permit-pty. An empty list: none.
		Extensions []string `yaml:"extensions"`
		// CriticalOptions are restrictions the SSH server enforces:
		// force-command, source-address, verify-required.
		CriticalOptions map[string]string `yaml:"critical_options"`
	} `yaml:"ssh"`
}

// isSSHBase reports whether a base is one of the SSH templates.
func isSSHBase(base string) bool {
	_, ok := ca.SSHTemplateByName(base)
	return ok
}

var (
	profileName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	keyUsages   = map[string]x509.KeyUsage{
		"digital_signature":  x509.KeyUsageDigitalSignature,
		"key_encipherment":   x509.KeyUsageKeyEncipherment,
		"content_commitment": x509.KeyUsageContentCommitment,
		"data_encipherment":  x509.KeyUsageDataEncipherment,
		"key_agreement":      x509.KeyUsageKeyAgreement,
	}
	extKeyUsages = map[string]x509.ExtKeyUsage{
		"server_auth":      x509.ExtKeyUsageServerAuth,
		"client_auth":      x509.ExtKeyUsageClientAuth,
		"email_protection": x509.ExtKeyUsageEmailProtection,
		"code_signing":     x509.ExtKeyUsageCodeSigning,
		"time_stamping":    x509.ExtKeyUsageTimeStamping,
		"ocsp_signing":     x509.ExtKeyUsageOCSPSigning,
	}
	// Extensions the CA sets itself; a profile cannot add them again.
	reservedExtensions = []string{
		"2.5.29.14", "2.5.29.15", "2.5.29.17", "2.5.29.19", "2.5.29.30", "2.5.29.31",
		"2.5.29.32", "2.5.29.35", "2.5.29.37", "1.3.6.1.5.5.7.1.1",
	}
	maxProfileValidity = 10 * 365 * 24 * time.Hour
)

// X509Template returns the X.509 template with that name: a profile, or
// a built-in one.
func (c *Config) X509Template(name string) (ca.X509Template, bool) {
	profiles, err := c.X509Profiles()
	if err == nil {
		for _, p := range profiles {
			if p.Name == name {
				return p, true
			}
		}
	}
	return ca.X509TemplateByName(name)
}

// SSHTemplate returns the SSH template with that name: a profile, or a
// built-in one.
func (c *Config) SSHTemplate(name string) (ca.SSHTemplate, bool) {
	profiles, err := c.SSHProfiles()
	if err == nil {
		for _, p := range profiles {
			if p.Name == name {
				return p, true
			}
		}
	}
	return ca.SSHTemplateByName(name)
}

// checkProfileNames checks every profile's name: well formed, not a
// built-in one, used once.
func (c *Config) checkProfileNames() error {
	seen := map[string]bool{}
	for i, p := range c.Profiles {
		where := profileWhere(i, p)
		if !profileName.MatchString(p.Name) {
			return fmt.Errorf("%s: the name must be lower case letters, digits and dashes, e.g. device-client", where)
		}
		_, builtInX509 := ca.X509TemplateByName(p.Name)
		if builtInX509 || isSSHBase(p.Name) || strings.HasPrefix(p.Name, "ssh-") || p.Name == "bastionxp-ca-server" {
			return fmt.Errorf("%s: the name is taken by a built-in profile", where)
		}
		if seen[p.Name] {
			return fmt.Errorf("%s: the name is used twice", where)
		}
		seen[p.Name] = true
	}
	return nil
}

func profileWhere(i int, p Profile) string {
	if p.Name != "" {
		return "profile " + p.Name
	}
	return fmt.Sprintf("profiles[%d]", i)
}

// X509Profiles turns the X.509 profiles into templates for the CA, and
// checks them.
func (c *Config) X509Profiles() ([]ca.X509Template, error) {
	if err := c.checkProfileNames(); err != nil {
		return nil, err
	}
	var out []ca.X509Template
	for i, p := range c.Profiles {
		if isSSHBase(p.Base) {
			continue
		}
		t, err := p.template()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", profileWhere(i, p), err)
		}
		out = append(out, t)
	}
	return out, nil
}

// SSHProfiles turns the SSH profiles into templates for the CA, and
// checks them.
func (c *Config) SSHProfiles() ([]ca.SSHTemplate, error) {
	if err := c.checkProfileNames(); err != nil {
		return nil, err
	}
	var out []ca.SSHTemplate
	for i, p := range c.Profiles {
		if !isSSHBase(p.Base) {
			continue
		}
		t, err := p.sshTemplate()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", profileWhere(i, p), err)
		}
		out = append(out, t)
	}
	return out, nil
}

// sshTemplate turns an SSH profile into a template.
func (p Profile) sshTemplate() (ca.SSHTemplate, error) {
	t, _ := ca.SSHProfileBase(p.Base, p.Name)
	// The X.509 settings mean nothing for an SSH certificate. Say so
	// rather than ignore them.
	switch {
	case len(p.KeyUsage) > 0 || len(p.ExtKeyUsage) > 0:
		return t, errors.New("key_usage and ext_key_usage are for X.509 profiles, not SSH ones")
	case len(p.Subject.OrganizationalUnit) > 0 || p.Subject.RequireCommonName:
		return t, errors.New("subject is for X.509 profiles, not SSH ones")
	case p.Names != nil || len(p.Policies) > 0 || len(p.Extensions) > 0 || p.Keys != nil:
		return t, errors.New("names, policies, extensions and keys are for X.509 profiles; SSH profiles take ssh.extensions and ssh.critical_options")
	}
	if err := applyLifetimes(&t.DefaultValidity, &t.MaxValidity, p.Validity, p.MaxValidity); err != nil {
		return t, err
	}
	if p.SSH == nil {
		return t, nil
	}
	if t.CertType == ssh.HostCert && (p.SSH.Extensions != nil || len(p.SSH.CriticalOptions) > 0) {
		return t, errors.New("ssh.extensions and ssh.critical_options are for user certificates; host certificates have none")
	}
	if p.SSH.Extensions != nil {
		t.Extensions = map[string]string{}
		for _, e := range p.SSH.Extensions {
			if !slices.Contains(ca.SSHUserExtensions, e) {
				return t, fmt.Errorf("ssh.extensions: unknown %q; use %s", e, strings.Join(ca.SSHUserExtensions, ", "))
			}
			t.Extensions[e] = ""
		}
	}
	for option, value := range p.SSH.CriticalOptions {
		if !slices.Contains(ca.SSHCriticalOptions, option) {
			return t, fmt.Errorf("ssh.critical_options: unknown %q; use %s", option, strings.Join(ca.SSHCriticalOptions, ", "))
		}
		switch option {
		case "source-address":
			for _, cidr := range strings.Split(value, ",") {
				cidr = strings.TrimSpace(cidr)
				if _, _, err := net.ParseCIDR(cidr); err != nil && net.ParseIP(cidr) == nil {
					return t, fmt.Errorf("ssh.critical_options.source-address: %q is not an address or range", cidr)
				}
			}
		case "force-command":
			if strings.TrimSpace(value) == "" {
				return t, errors.New("ssh.critical_options.force-command is empty")
			}
		case "verify-required":
			// A flag: its value is empty.
			value = ""
		}
		if t.CriticalOptions == nil {
			t.CriticalOptions = map[string]string{}
		}
		t.CriticalOptions[option] = value
	}
	return t, nil
}

// applyLifetimes sets a profile's default and maximum lifetime.
func applyLifetimes(def, max *time.Duration, validity, maxValidity string) error {
	if validity != "" {
		d, err := parseLifetime(validity)
		if err != nil {
			return fmt.Errorf("validity: %w", err)
		}
		*def = d
		if maxValidity == "" && d > *max {
			*max = d
		}
	}
	if maxValidity != "" {
		d, err := parseLifetime(maxValidity)
		if err != nil {
			return fmt.Errorf("max_validity: %w", err)
		}
		*max = d
	}
	if *def > *max {
		return errors.New("validity is longer than max_validity")
	}
	return nil
}

func (p Profile) template() (ca.X509Template, error) {
	t, ok := ca.ProfileBase(p.Base, p.Name)
	if !ok {
		return t, fmt.Errorf("base must be one of %s, ssh-user, ssh-host; got %q", strings.Join(ca.ProfileBases(), ", "), p.Base)
	}
	if p.SSH != nil {
		return t, errors.New("ssh is for SSH profiles (base ssh-user or ssh-host)")
	}
	if err := applyLifetimes(&t.DefaultValidity, &t.MaxValidity, p.Validity, p.MaxValidity); err != nil {
		return t, err
	}
	for _, u := range p.KeyUsage {
		bit, ok := keyUsages[u]
		if !ok {
			return t, fmt.Errorf("key_usage: unknown %q", u)
		}
		t.KeyUsage |= bit
	}
	if len(p.ExtKeyUsage) > 0 {
		t.ExtKeyUsage = nil
		for _, u := range p.ExtKeyUsage {
			eku, ok := extKeyUsages[u]
			if !ok {
				return t, fmt.Errorf("ext_key_usage: unknown %q", u)
			}
			t.ExtKeyUsage = append(t.ExtKeyUsage, eku)
		}
	}
	// A server certificate is of no use without a host name.
	t.RequireHostName = slices.Contains(t.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	for _, ou := range p.Subject.OrganizationalUnit {
		if strings.TrimSpace(ou) == "" {
			return t, errors.New("subject.organizational_unit has an empty entry")
		}
	}
	t.OrganizationalUnit = p.Subject.OrganizationalUnit
	t.RequireCommonName = t.RequireCommonName || p.Subject.RequireCommonName
	if p.Names != nil {
		t.Names = &ca.NamePolicy{DNS: p.Names.DNS, IP: p.Names.IP, Email: p.Names.Email, Wildcard: p.Names.Wildcard}
		if p.Names.Wildcard && !p.Names.DNS {
			return t, errors.New("names.wildcard needs names.dns")
		}
	}
	if t.RequireHostName && t.Names != nil && !t.Names.DNS && !t.Names.IP {
		return t, errors.New("server_auth needs a host name, but names allows neither dns nor ip")
	}
	for _, o := range p.Policies {
		oid, err := parseOID(o)
		if err != nil {
			return t, fmt.Errorf("policies: %w", err)
		}
		t.Policies = append(t.Policies, oid)
	}
	for _, e := range p.Extensions {
		oid, err := parseOID(e.OID)
		if err != nil {
			return t, fmt.Errorf("extensions: %w", err)
		}
		if slices.Contains(reservedExtensions, oid.String()) {
			return t, fmt.Errorf("extensions: %s is set by the CA itself; use the profile's own setting for it", oid)
		}
		value, err := hex.DecodeString(strings.ReplaceAll(e.ValueHex, ":", ""))
		if err != nil || len(value) == 0 {
			return t, fmt.Errorf("extensions: value_hex of %s is not hex", oid)
		}
		var raw asn1.RawValue
		if rest, err := asn1.Unmarshal(value, &raw); err != nil || len(rest) > 0 {
			return t, fmt.Errorf("extensions: the value of %s is not one DER value", oid)
		}
		t.Extensions = append(t.Extensions, pkix.Extension{Id: oid, Critical: e.Critical, Value: value})
	}
	if k := p.Keys; k != nil {
		for _, a := range k.Algorithms {
			if a != "ecdsa" && a != "rsa" && a != "ed25519" {
				return t, fmt.Errorf("keys.algorithms: unknown %q; use ecdsa, rsa, ed25519", a)
			}
		}
		for _, c := range k.Curves {
			if c != "P-256" && c != "P-384" && c != "P-521" {
				return t, fmt.Errorf("keys.curves: unknown %q; use P-256, P-384, P-521", c)
			}
		}
		if k.MinRSABits != 0 && (k.MinRSABits < 2048 || k.MinRSABits > 8192) {
			return t, errors.New("keys.min_rsa_bits must be between 2048 and 8192")
		}
		t.Keys = &ca.KeyPolicy{Algorithms: k.Algorithms, MinRSABits: k.MinRSABits, Curves: k.Curves}
	}
	return t, nil
}

// parseLifetime reads "365d", or a Go duration such as "8h" or "90m".
func parseLifetime(s string) (time.Duration, error) {
	var d time.Duration
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil {
			return 0, fmt.Errorf("%q is not a lifetime: use a form like 365d or 8h", s)
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, fmt.Errorf("%q is not a lifetime: use a form like 365d or 8h", s)
		}
	}
	if d < time.Minute || d > maxProfileValidity {
		return 0, fmt.Errorf("%q is out of range: between 1 minute and 10 years", s)
	}
	return d, nil
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("%q is not an OID: use a form like 1.3.6.1.4.1.55555.1", s)
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%q is not an OID: use a form like 1.3.6.1.4.1.55555.1", s)
		}
		oid[i] = n
	}
	return oid, nil
}
