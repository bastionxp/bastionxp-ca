// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package config loads and validates the BastionXP CA configuration file.
//
// The whole configuration is one YAML file decoded into one Config struct.
// Load it once in main and pass the values to the packages that need them.
// Nothing in this package is global.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"go.yaml.in/yaml/v3"

	"github.com/bastionxp/bastionxp-ca/internal/acme"
	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/ldap"
)

// Key types accepted in ca.key_type.
const (
	KeyTypeECDSA = "ecdsa"
	KeyTypeRSA   = "rsa"
)

// Config is the top level of the configuration file.
type Config struct {
	// DataDir is the directory that holds the CA keys and certificates.
	DataDir string  `yaml:"data_dir"`
	CA      CA      `yaml:"ca"`
	Server  Server  `yaml:"server"`
	ACME    ACME    `yaml:"acme"`
	SCEP    SCEP    `yaml:"scep"`
	OIDC    OIDC    `yaml:"oidc"`
	LDAP    LDAP    `yaml:"ldap"`
	Metrics Metrics `yaml:"metrics"`
	// Profiles are certificate templates of your own, beside the built-in
	// ones. See profiles.go.
	Profiles []Profile `yaml:"profiles"`
	// Access are the rules for people who log in, with OIDC or LDAP: who
	// gets which SSH principals, and who is an admin.
	Access []AccessRule `yaml:"access"`
}

// OIDC turns on login with an OpenID Connect identity provider: Microsoft
// Entra ID, AD FS, Google, Okta, Keycloak and others. Leave the whole
// section out to run without it.
type OIDC struct {
	// Issuer is the provider's address, e.g.
	// "https://login.microsoftonline.com/<tenant-id>/v2.0".
	Issuer string `yaml:"issuer"`
	// ClientID and ClientSecret are those of the CA's registration at
	// the provider. Its redirect URI must be server.url followed by
	// "/v1/oidc/callback".
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	// ClientSecretFile is a file with the client secret, instead of
	// ClientSecret, so that the configuration file holds no secret.
	ClientSecretFile string `yaml:"client_secret_file"`
	// UsernameClaim names the claim with the person's name. Default:
	// "preferred_username".
	UsernameClaim string `yaml:"username_claim"`
	// GroupsClaim names the claim with the person's groups. Default:
	// "groups".
	GroupsClaim string `yaml:"groups_claim"`
	// Scopes are asked for at the login. Default: openid, profile, email.
	Scopes []string `yaml:"scopes"`
	// X509 and SSH say which profiles people who log in get for
	// themselves: a TLS client certificate and an SSH user certificate.
	X509 CertProfile `yaml:"x509"`
	SSH  CertProfile `yaml:"ssh"`
}

// CertProfile names the profile a verifier issues certificates with.
type CertProfile struct {
	// CertProfile is a built-in profile or one of the profiles section.
	// Empty: the verifier's default.
	CertProfile string `yaml:"cert_profile"`
}

// Or returns the profile, or def if none is set.
func (p CertProfile) Or(def string) string {
	if p.CertProfile == "" {
		return def
	}
	return p.CertProfile
}

// LDAP turns on login with a username and password checked against a
// directory: Microsoft Active Directory, or another LDAP server. Leave the
// whole section out to run without it. The defaults fit Active Directory.
type LDAP struct {
	// URL is the directory's address: "ldaps://dc1.corp.example.com", or
	// "ldap://..." together with start_tls. Unencrypted LDAP is refused,
	// because passwords go over it.
	URL      string `yaml:"url"`
	StartTLS bool   `yaml:"start_tls"`
	// CAFile is a PEM file with the certificate(s) that issued the
	// directory's certificate, e.g. the company's AD CS root. Default:
	// those this machine trusts.
	CAFile string `yaml:"ca_file"`

	// BaseDN is where people are searched, e.g. "DC=corp,DC=example,DC=com".
	BaseDN string `yaml:"base_dn"`
	// BindDN is the CA's service account, which searches people and
	// groups; it needs to read them, nothing more.
	BindDN string `yaml:"bind_dn"`
	// BindPasswordFile is a file with the service account's password.
	// Keep it readable by the CA only.
	BindPasswordFile string `yaml:"bind_password_file"`

	// UserFilter finds the person by what they type; "{username}" is
	// replaced by it. Default: AD's sAMAccountName.
	UserFilter string `yaml:"user_filter"`
	// UsernameAttribute names the person in the access rules. Default:
	// "userPrincipalName" (alice@corp.example.com), as with OIDC at Entra
	// ID. "sAMAccountName" gives "alice".
	UsernameAttribute string `yaml:"username_attribute"`
	// GroupBaseDN is where groups are searched. Only groups below it
	// count. Default: base_dn.
	GroupBaseDN string `yaml:"group_base_dn"`
	// GroupFilter finds the person's groups; "{user_dn}" is replaced by
	// the name of their entry. Default: AD's groups, nested ones too.
	GroupFilter string `yaml:"group_filter"`
	// X509 and SSH: the profiles people get for themselves, as with OIDC.
	X509 CertProfile `yaml:"x509"`
	SSH  CertProfile `yaml:"ssh"`
}

// Metrics turns on a Prometheus endpoint, /metrics, on an address of its
// own. Leave the whole section out to run without it.
type Metrics struct {
	// Address is where the metrics are served, e.g. "127.0.0.1:9100".
	// Not the CA's own addresses: it is for monitoring, not for clients.
	Address string `yaml:"address"`
	// TokenFile is a file with a token that Prometheus must send as
	// "Authorization: Bearer <token>". Optional, and recommended unless
	// the address is reachable from this machine only.
	TokenFile string `yaml:"token_file"`
}

// Enabled reports whether login with LDAP is configured.
func (l LDAP) Enabled() bool { return l.URL != "" }

// AccessRule gives the people it matches the right to certificates. A
// person matches if their name is in Users or one of their groups is in
// Groups.
type AccessRule struct {
	Users  []string `yaml:"users"`
	Groups []string `yaml:"groups"`
	// SSHPrincipals are the login names on servers they may get SSH
	// user certificates for, themselves. "{username}" stands for the
	// person's name, "{short_username}" for the part before an "@".
	SSHPrincipals []string `yaml:"ssh_principals"`
	// Admin lets them get a one-time token for any certificate.
	Admin bool `yaml:"admin"`
}

// SCEP turns on the SCEP server, the protocol that phones, managed
// laptops, routers and printers use to get a certificate. Leave the whole
// section out to run without it.
type SCEP struct {
	// Enabled switches the SCEP server on.
	Enabled bool `yaml:"enabled"`
	// Static lets devices enroll with one shared challenge password, for
	// device management systems that cannot hand out a one-time token per
	// device. Optional.
	Static SCEPStatic `yaml:"static"`
}

// SCEPStatic is the shared challenge password of SCEP, and what a device
// may get with it. Anyone who knows the password can enroll, so keep the
// limits tight.
type SCEPStatic struct {
	// ChallengeFile is a file with the password, at least 16 characters.
	ChallengeFile string `yaml:"challenge_file"`
	// X509 is the profile of the certificates: "tls-device" (default),
	// "tls-client", "tls-server", or one of your own based on these.
	X509 CertProfile `yaml:"x509"`
	// DNSDomains are the only domains DNS names may be in; none listed,
	// no DNS names.
	DNSDomains []string `yaml:"dns_domains"`
	// EmailDomains are the only domains email addresses may be in; none
	// listed, no email addresses.
	EmailDomains []string `yaml:"email_domains"`
	// MaxPerHour limits the enrollments with the password, for the whole
	// CA. Default 100; 0 means no limit.
	MaxPerHour *int `yaml:"max_per_hour"`
}

// Enabled reports whether the static challenge is configured.
func (s SCEPStatic) Enabled() bool { return s.ChallengeFile != "" }

// DefaultSCEPStaticPerHour is the default of max_per_hour.
const DefaultSCEPStaticPerHour = 100

// PerHour returns max_per_hour with its default.
func (s SCEPStatic) PerHour() int {
	if s.MaxPerHour == nil {
		return DefaultSCEPStaticPerHour
	}
	return *s.MaxPerHour
}

// ACME turns on the ACME server, the protocol that tools such as certbot,
// acme.sh, lego and Caddy use to get TLS certificates by themselves. Leave
// the whole section out to run without it.
type ACME struct {
	// AllowedDomains are the domains ACME clients may get certificates
	// for. A name is allowed if it is one of these or ends with one of
	// them: "example.com" allows "example.com" and "web.example.com".
	AllowedDomains []string `yaml:"allowed_domains"`
	// AllowedIPRanges are the IP address ranges ACME clients may get
	// certificates for (RFC 8738), e.g. "10.0.0.0/8". Optional.
	AllowedIPRanges []string `yaml:"allowed_ip_ranges"`
	// DNSResolver is the DNS server the dns-01 challenge asks, e.g.
	// "10.0.0.53:53": best the one that holds the zones, so that no
	// cache answers "no such record" from before the client created it.
	// Optional: default, the resolvers of this machine.
	DNSResolver string `yaml:"dns_resolver"`
	// Limits per source. Each left out gets its default.
	Limits ACMELimits `yaml:"limits"`
	// Challenges are the challenge types ACME clients may use:
	// "http-01", "dns-01", "tls-alpn-01". Default: all three.
	Challenges []string `yaml:"challenges"`
	// X509 is the profile of ACME certificates: "tls-server" (default),
	// or one of your own based on it.
	X509 CertProfile `yaml:"x509"`
}

// Enabled reports whether the ACME server is on: it is when it may issue
// for some domain or IP range.
func (a ACME) Enabled() bool { return len(a.AllowedDomains) > 0 || len(a.AllowedIPRanges) > 0 }

// IPRanges returns AllowedIPRanges parsed. Call it on a validated
// configuration.
func (a ACME) IPRanges() []*net.IPNet {
	var ranges []*net.IPNet
	for _, r := range a.AllowedIPRanges {
		if _, n, err := net.ParseCIDR(r); err == nil {
			ranges = append(ranges, n)
		}
	}
	return ranges
}

// ACMELimits limit what one source can ask of the ACME server, per hour.
// 0 means no limit.
type ACMELimits struct {
	// AccountsPerIPPerHour is the most new accounts from one IP address.
	// Default 100.
	AccountsPerIPPerHour *int `yaml:"accounts_per_ip_per_hour"`
	// OrdersPerAccountPerHour is the most new orders from one account.
	// Default 300.
	OrdersPerAccountPerHour *int `yaml:"orders_per_account_per_hour"`
}

// Resolved returns the limits with the defaults filled in.
func (l ACMELimits) Resolved() acme.Limits {
	limits := acme.DefaultLimits
	if l.AccountsPerIPPerHour != nil {
		limits.AccountsPerIP = *l.AccountsPerIPPerHour
	}
	if l.OrdersPerAccountPerHour != nil {
		limits.OrdersPerAccount = *l.OrdersPerAccountPerHour
	}
	return limits
}

// Server describes the HTTPS server started by "bxp serve".
type Server struct {
	// Address is where the server listens, e.g. ":8443" or "10.0.0.5:443".
	Address string `yaml:"address"`
	// Names are the DNS names and IP addresses clients use to reach the
	// server. They go into the server's own TLS certificate.
	Names []string `yaml:"names"`
	// URL is the address people's browsers use to reach the server, e.g.
	// "https://ca.example.com:8443". Only needed for login with the identity provider.
	URL string `yaml:"url"`

	// PublicAddress is where the server also listens with plain HTTP,
	// e.g. ":8080", for the CA's public information only: its
	// certificates, the list of revoked certificates (CRL) and OCSP.
	// Optional.
	PublicAddress string `yaml:"public_address"`
	// PublicURL is the address others use to reach that public
	// information, e.g. "http://ca.example.com:8080". If set, it is
	// written into every TLS certificate, so that programs can find out
	// by themselves whether a certificate was revoked. Optional.
	PublicURL string `yaml:"public_url"`
}

// CA describes the certificate authority created by "bxp init".
type CA struct {
	// Name is used to build the CA certificate names, e.g. "<Name> Root CA".
	Name string `yaml:"name"`
	// Organization is the O field of the CA certificates and of every
	// certificate the CA issues.
	Organization string `yaml:"organization"`
	// KeyType is "ecdsa" (default) or "rsa".
	KeyType string `yaml:"key_type"`
	// KeyPassphraseFile is a file with the passphrase of the keys the
	// server uses, if they are encrypted. It must not be inside data_dir:
	// a backup of data_dir would then hold the keys and the passphrase.
	// Better still: the systemd credential "bastionxp-ca-key-passphrase",
	// sealed to the machine's TPM. Optional.
	KeyPassphraseFile string `yaml:"key_passphrase_file"`
	// NameConstraints limit the names the intermediate can sign for.
	// They are written into the intermediate by "bxp init" (and by
	// "bxp new-intermediate"): changing them here later changes
	// nothing until the next new intermediate. Optional.
	NameConstraints NameConstraints `yaml:"name_constraints"`
	// RootValidity is how long the root certificate is valid, e.g. "10y"
	// or "3650d". Used once, at init. Default 10y.
	RootValidity string `yaml:"root_validity"`
	// IntermediateValidity is how long the intermediate certificate is
	// valid, at init and at every new-intermediate. Default 3y. Not used
	// under an external root, whose CA decides.
	IntermediateValidity string `yaml:"intermediate_validity"`
}

// Defaults and bounds of the CA certificates' lifetimes.
const (
	year                        = 365 * 24 * time.Hour
	DefaultRootValidity         = 10 * year
	DefaultIntermediateValidity = 3 * year
	minCAValidity               = 1 * year
	maxRootValidity             = 30 * year
)

// RootLifetime returns ca.root_validity, or its default. The
// configuration was validated, so it parses.
func (c CA) RootLifetime() time.Duration {
	d, _ := parseCALifetime(c.RootValidity, DefaultRootValidity)
	return d
}

// IntermediateLifetime returns ca.intermediate_validity, or its default.
func (c CA) IntermediateLifetime() time.Duration {
	d, _ := parseCALifetime(c.IntermediateValidity, DefaultIntermediateValidity)
	return d
}

// parseCALifetime reads a CA lifetime: "10y", "3650d", or empty for the
// default.
func parseCALifetime(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	unit := time.Duration(0)
	switch {
	case strings.HasSuffix(s, "y"):
		unit = year
	case strings.HasSuffix(s, "d"):
		unit = 24 * time.Hour
	default:
		return 0, fmt.Errorf("%q is not a lifetime: use a form like 10y or 3650d", s)
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%q is not a lifetime: use a form like 10y or 3650d", s)
	}
	return time.Duration(n) * unit, nil
}

// NameConstraints are the names the CA may issue for. When any is given,
// a kind that is not listed (DNS, IP, email) is not allowed at all.
type NameConstraints struct {
	// DNSDomains: "example.com" allows it and every name below it;
	// ".example.com" only the names below it.
	DNSDomains []string `yaml:"dns_domains"`
	// IPRanges in CIDR form, e.g. "10.0.0.0/8".
	IPRanges []string `yaml:"ip_ranges"`
	// EmailDomains: "example.com" allows addresses at example.com,
	// ".example.com" at the domains below it.
	EmailDomains []string `yaml:"email_domains"`
}

// CA returns the constraints in the form the ca package takes. Call it
// on a validated configuration.
func (n NameConstraints) CA() ca.NameConstraints {
	out := ca.NameConstraints{DNSDomains: n.DNSDomains, EmailDomains: n.EmailDomains}
	for _, r := range n.IPRanges {
		if _, ipNet, err := net.ParseCIDR(r); err == nil {
			out.IPRanges = append(out.IPRanges, ipNet)
		}
	}
	return out
}

// Load reads the file at path, fills in defaults and validates the result.
// Unknown keys are an error, so a typo in the file is caught at startup.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	cfg.setDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) setDefaults() {
	if c.CA.Name == "" {
		c.CA.Name = "BastionXP"
	}
	if c.CA.KeyType == "" {
		c.CA.KeyType = KeyTypeECDSA
	}
	if c.Server.Address == "" {
		c.Server.Address = ":8443"
	}
	if len(c.Server.Names) == 0 {
		c.Server.Names = []string{"localhost", "127.0.0.1"}
	}
	if c.OIDC.Issuer != "" {
		if c.OIDC.UsernameClaim == "" {
			c.OIDC.UsernameClaim = "preferred_username"
		}
		if c.OIDC.GroupsClaim == "" {
			c.OIDC.GroupsClaim = "groups"
		}
		if len(c.OIDC.Scopes) == 0 {
			c.OIDC.Scopes = []string{"openid", "profile", "email"}
		}
	}
	c.setSCEPDefaults()
	if c.LDAP.Enabled() {
		if c.LDAP.UserFilter == "" {
			c.LDAP.UserFilter = ldap.DefaultUserFilter
		}
		if c.LDAP.UsernameAttribute == "" {
			c.LDAP.UsernameAttribute = ldap.DefaultUsernameAttribute
		}
		if c.LDAP.GroupFilter == "" {
			c.LDAP.GroupFilter = ldap.DefaultGroupFilter
		}
	}
}

// Validate reports the first problem found in the configuration.
func (c *Config) Validate() error {
	if c.DataDir == "" {
		return errors.New("data_dir is required")
	}
	if c.CA.Organization == "" {
		return errors.New("ca.organization is required")
	}
	switch c.CA.KeyType {
	case KeyTypeECDSA, KeyTypeRSA:
	default:
		return fmt.Errorf("ca.key_type must be %q or %q, got %q", KeyTypeECDSA, KeyTypeRSA, c.CA.KeyType)
	}
	root, err := parseCALifetime(c.CA.RootValidity, DefaultRootValidity)
	if err != nil {
		return fmt.Errorf("ca.root_validity: %w", err)
	}
	if root < minCAValidity || root > maxRootValidity {
		return fmt.Errorf("ca.root_validity must be between 1y and 30y, got %q", c.CA.RootValidity)
	}
	intermediate, err := parseCALifetime(c.CA.IntermediateValidity, DefaultIntermediateValidity)
	if err != nil {
		return fmt.Errorf("ca.intermediate_validity: %w", err)
	}
	if intermediate < minCAValidity || intermediate > root {
		got := fmt.Sprintf("%q", c.CA.IntermediateValidity)
		if c.CA.IntermediateValidity == "" {
			got = lifetimeText(intermediate) + " (the default)"
		}
		return fmt.Errorf("ca.intermediate_validity must be between 1y and the root's lifetime (%s), got %s",
			lifetimeText(root), got)
	}
	if c.CA.KeyPassphraseFile != "" && isInside(c.CA.KeyPassphraseFile, c.DataDir) {
		return errors.New("ca.key_passphrase_file must not be inside data_dir: every copy of data_dir would hold both the keys and their passphrase")
	}
	for _, name := range c.Server.Names {
		if name == "" {
			return errors.New("server.names must not contain an empty name")
		}
	}
	if c.Server.URL != "" {
		u, err := url.Parse(c.Server.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" {
			return fmt.Errorf("server.url must look like https://ca.example.com:8443, got %q", c.Server.URL)
		}
	}
	if c.Server.PublicURL != "" {
		u, err := url.Parse(c.Server.PublicURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Path != "" || u.RawQuery != "" {
			return fmt.Errorf("server.public_url must look like http://ca.example.com:8080, got %q", c.Server.PublicURL)
		}
	}
	if r := c.ACME.DNSResolver; r != "" {
		if !c.ACME.Enabled() {
			return errors.New("acme.dns_resolver is set, but ACME is off: give acme.allowed_domains")
		}
		host, port, err := net.SplitHostPort(r)
		if err != nil || host == "" || port == "" {
			return fmt.Errorf("acme.dns_resolver must look like 10.0.0.53:53, got %q", r)
		}
	}
	seenChallenge := map[string]bool{}
	for _, c := range c.ACME.Challenges {
		if !slices.Contains(acme.ChallengeTypes, c) {
			return fmt.Errorf("acme.challenges: %q is not a challenge type; use %s", c, strings.Join(acme.ChallengeTypes, ", "))
		}
		if seenChallenge[c] {
			return fmt.Errorf("acme.challenges: %q is listed twice", c)
		}
		seenChallenge[c] = true
	}
	for name, v := range map[string]*int{
		"accounts_per_ip_per_hour":    c.ACME.Limits.AccountsPerIPPerHour,
		"orders_per_account_per_hour": c.ACME.Limits.OrdersPerAccountPerHour,
	} {
		if v != nil && *v < 0 {
			return fmt.Errorf("acme.limits.%s must be 0 (no limit) or more, got %d", name, *v)
		}
	}
	for _, r := range c.ACME.AllowedIPRanges {
		if _, _, err := net.ParseCIDR(r); err != nil {
			return fmt.Errorf("acme.allowed_ip_ranges: %q is not a range, use a form like 10.0.0.0/8", r)
		}
	}
	for _, domain := range c.ACME.AllowedDomains {
		if domain == "" || strings.ContainsAny(domain, "*/ ") || strings.HasPrefix(domain, ".") {
			return fmt.Errorf("acme.allowed_domains: %q is not a domain name, use a form like example.com", domain)
		}
	}
	if c.OIDC.Issuer != "" && c.Server.URL == "" {
		return errors.New("server.url is required for login with OIDC: the address browsers use to reach this server")
	}
	if err := c.validateOIDC(); err != nil {
		return err
	}
	if err := c.validateLDAP(); err != nil {
		return err
	}
	if err := c.validateNameConstraints(); err != nil {
		return err
	}
	if _, err := c.X509Profiles(); err != nil {
		return err
	}
	if _, err := c.SSHProfiles(); err != nil {
		return err
	}
	if err := c.validateSCEPStatic(); err != nil {
		return err
	}
	if err := c.validateVerifierProfiles(); err != nil {
		return err
	}
	if c.Metrics.Address == "" && c.Metrics.TokenFile != "" {
		return errors.New("metrics.address is required when metrics.token_file is given")
	}
	if c.Metrics.Address != "" {
		if _, _, err := net.SplitHostPort(c.Metrics.Address); err != nil {
			return fmt.Errorf("metrics.address must look like 127.0.0.1:9100, got %q", c.Metrics.Address)
		}
		if c.Metrics.Address == c.Server.Address || (c.Server.PublicAddress != "" && c.Metrics.Address == c.Server.PublicAddress) {
			return errors.New("metrics.address must be an address of its own, not one of the server's")
		}
	}
	return c.validateAccess()
}

func (c *Config) validateOIDC() error {
	o := c.OIDC
	if o.Issuer == "" {
		if o.ClientID != "" || o.ClientSecret != "" || o.ClientSecretFile != "" || o.UsernameClaim != "" || o.GroupsClaim != "" || len(o.Scopes) > 0 ||
			o.X509.CertProfile != "" || o.SSH.CertProfile != "" {
			return errors.New("oidc.issuer is required when other oidc settings are given")
		}
		return nil
	}
	u, err := url.Parse(o.Issuer)
	// Plain http only for a provider on this machine, as in tests.
	loopback := u != nil && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1")
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && loopback)) {
		return fmt.Errorf("oidc.issuer must look like https://login.example.com/..., got %q", o.Issuer)
	}
	if o.ClientID == "" || (o.ClientSecret == "" && o.ClientSecretFile == "") {
		return errors.New("oidc.client_id and oidc.client_secret_file (or client_secret) are required: copy them from the CA's registration at the provider")
	}
	if o.ClientSecret != "" && o.ClientSecretFile != "" {
		return errors.New("give oidc.client_secret or oidc.client_secret_file, not both")
	}
	return nil
}

func (c *Config) validateNameConstraints() error {
	n := c.CA.NameConstraints
	for _, list := range [][]string{n.DNSDomains, n.EmailDomains} {
		for _, d := range list {
			if d == "" || d == "." || strings.ContainsAny(d, "*@/: ") {
				return fmt.Errorf("ca.name_constraints: %q is not a domain, use a form like example.com", d)
			}
		}
	}
	for _, r := range n.IPRanges {
		if _, _, err := net.ParseCIDR(r); err != nil {
			return fmt.Errorf("ca.name_constraints.ip_ranges: %q is not a range, use a form like 10.0.0.0/8", r)
		}
	}
	constraints := n.CA()
	if constraints.IsZero() {
		return nil
	}
	// The server's own certificate, and what ACME may ask for, must fit:
	// the CA would refuse to issue them.
	for _, name := range c.Server.Names {
		if !constraints.Permits(name) {
			return fmt.Errorf("server.names: %q is outside ca.name_constraints", name)
		}
	}
	for _, domain := range c.ACME.AllowedDomains {
		if !constraints.Permits(domain) {
			return fmt.Errorf("acme.allowed_domains: %q is outside ca.name_constraints", domain)
		}
	}
	for _, r := range c.ACME.IPRanges() {
		if !constraints.Permits(r.IP.String()) || !constraints.Permits(lastIP(r).String()) {
			return fmt.Errorf("acme.allowed_ip_ranges: %s is outside ca.name_constraints", r)
		}
	}
	return nil
}

func (c *Config) setSCEPDefaults() {
	if c.SCEP.Static.Enabled() {
		c.SCEP.Static.X509.CertProfile = c.SCEP.Static.X509.Or(DefaultSCEPProfile)
	}
}

func (c *Config) validateSCEPStatic() error {
	s := c.SCEP.Static
	if !s.Enabled() {
		if s.X509.CertProfile != "" || len(s.DNSDomains)+len(s.EmailDomains) > 0 || s.MaxPerHour != nil {
			return errors.New("scep.static.challenge_file is required when other scep.static settings are given")
		}
		return nil
	}
	if !c.SCEP.Enabled {
		return errors.New("scep.static is set, but SCEP is off: set scep.enabled")
	}
	template, err := c.checkX509Profile("scep.static.x509.cert_profile", s.X509.CertProfile, "tls-client", "tls-server")
	if err != nil {
		return err
	}
	if template.RequireHostName && len(s.DNSDomains) == 0 {
		return fmt.Errorf("scep.static.dns_domains is required for %s: its certificates need a host name", template.Name)
	}
	for _, list := range [][]string{s.DNSDomains, s.EmailDomains} {
		for _, d := range list {
			if d == "" || strings.HasPrefix(d, ".") || strings.ContainsAny(d, "*@/: ") {
				return fmt.Errorf("scep.static: %q is not a domain, use a form like example.com", d)
			}
		}
	}
	if s.MaxPerHour != nil && *s.MaxPerHour < 0 {
		return fmt.Errorf("scep.static.max_per_hour must be 0 (no limit) or more, got %d", *s.MaxPerHour)
	}
	return nil
}

func (c *Config) validateLDAP() error {
	l := c.LDAP
	if !l.Enabled() {
		if l != (LDAP{}) {
			return errors.New("ldap.url is required when other ldap settings are given")
		}
		return nil
	}
	u, err := url.Parse(l.URL)
	if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("ldap.url must look like ldaps://dc1.corp.example.com, got %q", l.URL)
	}
	switch {
	case u.Scheme == "ldaps" && l.StartTLS:
		return errors.New("ldap.start_tls is for ldap:// addresses; ldaps:// is encrypted already")
	case u.Scheme == "ldap" && !l.StartTLS:
		return errors.New("ldap.url is unencrypted, and passwords would go over it: use ldaps://, or set start_tls: true")
	case u.Scheme != "ldaps" && u.Scheme != "ldap":
		return fmt.Errorf("ldap.url must start with ldaps://, got %q", l.URL)
	}
	if l.BaseDN == "" {
		return errors.New("ldap.base_dn is required, e.g. DC=corp,DC=example,DC=com")
	}
	if l.BindDN == "" || l.BindPasswordFile == "" {
		return errors.New("ldap.bind_dn and ldap.bind_password_file are required: the CA's service account that searches the directory")
	}
	for _, dn := range []string{l.BaseDN, l.BindDN, l.GroupBaseDN} {
		if _, err := goldap.ParseDN(dn); dn != "" && err != nil {
			return fmt.Errorf("ldap: %q is not a valid DN", dn)
		}
	}
	if !strings.Contains(l.UserFilter, "{username}") {
		return errors.New("ldap.user_filter must contain {username}")
	}
	if !strings.Contains(l.GroupFilter, "{user_dn}") {
		return errors.New("ldap.group_filter must contain {user_dn}")
	}
	for _, filter := range []string{l.UserFilter, l.GroupFilter} {
		if _, err := goldap.CompileFilter(strings.NewReplacer("{username}", "x", "{user_dn}", "x").Replace(filter)); err != nil {
			return fmt.Errorf("ldap: %q is not a valid search filter: %v", filter, err)
		}
	}
	return nil
}

// validateAccess checks the access rules, and that they fit the login.
func (c *Config) validateAccess() error {
	login := c.OIDC.Issuer != "" || c.LDAP.Enabled()
	if len(c.Access) > 0 && !login {
		return errors.New("the access rules are for people who log in: configure oidc or ldap too")
	}
	if login && len(c.Access) == 0 {
		return errors.New("login is configured, but nobody may log in: add access rules")
	}
	for i, rule := range c.Access {
		where := fmt.Sprintf("access rule %d", i+1)
		if len(rule.Users) == 0 && len(rule.Groups) == 0 {
			return fmt.Errorf("%s: say whom it is for, with users or groups", where)
		}
		if len(rule.SSHPrincipals) == 0 && !rule.Admin {
			return fmt.Errorf("%s: give ssh_principals, or admin: true", where)
		}
		for _, list := range [][]string{rule.Users, rule.Groups, rule.SSHPrincipals} {
			for _, item := range list {
				if strings.TrimSpace(item) == "" {
					return fmt.Errorf("%s: contains an empty entry", where)
				}
			}
		}
		for _, principal := range rule.SSHPrincipals {
			rest := strings.NewReplacer("{username}", "", "{short_username}", "").Replace(principal)
			if strings.ContainsAny(rest, "{}") {
				return fmt.Errorf("%s: %q has an unknown placeholder; use {username} or {short_username}", where, principal)
			}
		}
	}
	return nil
}

// isInside reports whether path is dir or lies below it.
func isInside(path, dir string) bool {
	absPath, err1 := filepath.Abs(path)
	absDir, err2 := filepath.Abs(dir)
	if err1 != nil || err2 != nil {
		return false
	}
	rel, err := filepath.Rel(absDir, absPath)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// lastIP is the highest address of a range.
func lastIP(n *net.IPNet) net.IP {
	ip := make(net.IP, len(n.IP))
	for i := range n.IP {
		ip[i] = n.IP[i] | ^n.Mask[i]
	}
	return ip
}

// lifetimeText writes a CA lifetime in years, or days if not whole years.
func lifetimeText(d time.Duration) string {
	if d%year == 0 {
		return strconv.Itoa(int(d/year)) + "y"
	}
	return strconv.Itoa(int(d/(24*time.Hour))) + "d"
}

// The profiles each verifier issues when its cert_profile is not set.
const (
	DefaultLoginX509Profile = "tls-client"
	DefaultLoginSSHProfile  = "ssh-user"
	DefaultACMEProfile      = "tls-server"
	DefaultSCEPProfile      = "tls-device"
)

// checkX509Profile checks a verifier's x509.cert_profile: it must exist,
// and be one of bases or a profile based on one of them.
func (c *Config) checkX509Profile(where, name string, bases ...string) (ca.X509Template, error) {
	t, ok := c.X509Template(name)
	if !ok {
		return t, fmt.Errorf("%s: no X.509 profile %q", where, name)
	}
	if !slices.Contains(bases, t.Base) {
		return t, fmt.Errorf("%s: %q is based on %s; it must be %s, or a profile based on it",
			where, name, t.Base, strings.Join(bases, " or "))
	}
	return t, nil
}

// checkSSHProfile checks a verifier's ssh.cert_profile: ssh-user, or a
// profile based on it.
func (c *Config) checkSSHProfile(where, name string) error {
	t, ok := c.SSHTemplate(name)
	if !ok {
		return fmt.Errorf("%s: no SSH profile %q", where, name)
	}
	if t.Base != "ssh-user" {
		return fmt.Errorf("%s: %q is based on %s; it must be ssh-user, or a profile based on it", where, name, t.Base)
	}
	return nil
}

// validateVerifierProfiles checks the cert_profile of every verifier.
func (c *Config) validateVerifierProfiles() error {
	if c.OIDC.Issuer != "" {
		if _, err := c.checkX509Profile("oidc.x509.cert_profile", c.OIDC.X509.Or(DefaultLoginX509Profile), "tls-client"); err != nil {
			return err
		}
		if err := c.checkSSHProfile("oidc.ssh.cert_profile", c.OIDC.SSH.Or(DefaultLoginSSHProfile)); err != nil {
			return err
		}
	}
	if c.LDAP.Enabled() {
		if _, err := c.checkX509Profile("ldap.x509.cert_profile", c.LDAP.X509.Or(DefaultLoginX509Profile), "tls-client"); err != nil {
			return err
		}
		if err := c.checkSSHProfile("ldap.ssh.cert_profile", c.LDAP.SSH.Or(DefaultLoginSSHProfile)); err != nil {
			return err
		}
	}
	if c.ACME.X509.CertProfile != "" && !c.ACME.Enabled() {
		return errors.New("acme.x509.cert_profile is set, but ACME is off: give acme.allowed_domains")
	}
	if c.ACME.Enabled() {
		if _, err := c.checkX509Profile("acme.x509.cert_profile", c.ACME.X509.Or(DefaultACMEProfile), "tls-server"); err != nil {
			return err
		}
	}
	return nil
}
