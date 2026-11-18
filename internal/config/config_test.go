// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bastionxp-ca.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Loading a minimal configuration fills in the defaults: ECDSA keys, the CA
// name, the server address and names.
func TestLoadAppliesDefaults(t *testing.T) {
	path := writeConfig(t, "data_dir: /tmp/x\nca:\n  organization: Example Org\n")

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CA.KeyType != KeyTypeECDSA {
		t.Errorf("default key type = %q, want %q", cfg.CA.KeyType, KeyTypeECDSA)
	}
	if cfg.CA.Name != "BastionXP" {
		t.Errorf("default name = %q, want BastionXP", cfg.CA.Name)
	}
	if cfg.Server.Address != ":8443" {
		t.Errorf("default server address = %q, want :8443", cfg.Server.Address)
	}
	if len(cfg.Server.Names) == 0 {
		t.Error("default server names are empty")
	}
}

// Every invalid configuration is refused with a message that names the
// setting: unknown keys, missing required settings, bad server and public
// URLs, bad ACME domains, IP ranges, resolvers, limits and challenges,
// access rules that name nobody or give nothing, incomplete or unsafe OIDC
// and LDAP settings, a key passphrase inside the data directory, bad metrics
// settings, names outside the name constraints, bad SCEP static settings and
// an unknown key type.
func TestLoadRejectsBadConfig(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{"unknown key", "data_dir: /tmp/x\nca:\n  organization: O\n  key_typ: rsa\n", "key_typ"},
		{"missing data_dir", "ca:\n  organization: O\n", "data_dir is required"},
		{"missing organization", "data_dir: /tmp/x\n", "ca.organization is required"},
		{"empty server name", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  names: [\"\"]\n", "server.names"},
		{"server URL without https", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  url: http://ca.example.com\n", "server.url must look like"},
		{"server URL with a path", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  url: https://ca.example.com/ca\n", "server.url must look like"},
		{"server URL without a scheme", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  url: ca.example.com:8443\n", "server.url must look like"},
		{"acme empty domain", "data_dir: /tmp/x\nca:\n  organization: O\nacme:\n  allowed_domains: [\"\"]\n", "acme.allowed_domains"},
		{"acme wildcard domain", "data_dir: /tmp/x\nca:\n  organization: O\nacme:\n  allowed_domains: [\"*.example.com\"]\n", "acme.allowed_domains"},
		{"acme domain with leading dot", "data_dir: /tmp/x\nca:\n  organization: O\nacme:\n  allowed_domains: [.example.com]\n", "acme.allowed_domains"},
		{"acme URL instead of domain", "data_dir: /tmp/x\nca:\n  organization: O\nacme:\n  allowed_domains: [\"https://example.com\"]\n", "acme.allowed_domains"},
		{"public URL with a path", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  public_url: http://ca.example.com/pki\n", "server.public_url"},
		{"public URL without a scheme", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  public_url: ca.example.com:8080\n", "server.public_url"},
		{"public URL with another scheme", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  public_url: ldap://ca.example.com\n", "server.public_url"},
		{"access without any login", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  url: https://ca.example.com\naccess:\n  - groups: [g]\n    admin: true\n", "configure oidc or ldap too"},
		{"oidc settings without issuer", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  url: https://ca.example.com\noidc:\n  client_id: id\n", "oidc.issuer is required"},
		{"oidc issuer over plain http", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  url: https://ca.example.com\noidc:\n  issuer: http://login.example.com\n  client_id: id\n  client_secret: s\naccess:\n  - groups: [g]\n    admin: true\n", "oidc.issuer must look like"},
		{"oidc without client secret", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  url: https://ca.example.com\noidc:\n  issuer: https://login.example.com\n  client_id: id\naccess:\n  - groups: [g]\n    admin: true\n", "client_secret"},
		{"oidc without access rules", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  url: https://ca.example.com\noidc:\n  issuer: https://login.example.com\n  client_id: id\n  client_secret: s\n", "nobody may log in"},
		{"oidc without server url", "data_dir: /tmp/x\nca:\n  organization: O\noidc:\n  issuer: https://login.example.com\n  client_id: id\n  client_secret: s\naccess:\n  - groups: [g]\n    admin: true\n", "server.url is required"},
		{"rule for nobody", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  url: https://ca.example.com\noidc:\n  issuer: https://login.example.com\n  client_id: id\n  client_secret: s\naccess:\n  - ssh_principals: [x]\n", "users or groups"},
		{"rule giving nothing", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  url: https://ca.example.com\noidc:\n  issuer: https://login.example.com\n  client_id: id\n  client_secret: s\naccess:\n  - groups: [g]\n", "ssh_principals, or admin"},
		{"rule with an empty group", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  url: https://ca.example.com\noidc:\n  issuer: https://login.example.com\n  client_id: id\n  client_secret: s\naccess:\n  - groups: [\"\"]\n    admin: true\n", "empty entry"},
		{"unknown placeholder", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  url: https://ca.example.com\noidc:\n  issuer: https://login.example.com\n  client_id: id\n  client_secret: s\naccess:\n  - groups: [g]\n    ssh_principals: [\"{email}\"]\n", "unknown placeholder"},
		{"ldap settings without url", "data_dir: /tmp/x\nca:\n  organization: O\nldap:\n  base_dn: DC=x\n", "ldap.url is required"},
		{"ldap unencrypted", "data_dir: /tmp/x\nca:\n  organization: O\nldap:\n  url: ldap://dc1.example.com\n  base_dn: DC=x\n  bind_dn: CN=s,DC=x\n  bind_password_file: /p\naccess:\n  - groups: [g]\n    admin: true\n", "unencrypted"},
		{"ldap start_tls on ldaps", "data_dir: /tmp/x\nca:\n  organization: O\nldap:\n  url: ldaps://dc1.example.com\n  start_tls: true\n  base_dn: DC=x\n  bind_dn: CN=s,DC=x\n  bind_password_file: /p\naccess:\n  - groups: [g]\n    admin: true\n", "encrypted already"},
		{"ldap other scheme", "data_dir: /tmp/x\nca:\n  organization: O\nldap:\n  url: https://dc1.example.com\n  base_dn: DC=x\n  bind_dn: CN=s,DC=x\n  bind_password_file: /p\naccess:\n  - groups: [g]\n    admin: true\n", "ldaps://"},
		{"ldap without base_dn", "data_dir: /tmp/x\nca:\n  organization: O\nldap:\n  url: ldaps://dc1.example.com\n  bind_dn: CN=s,DC=x\n  bind_password_file: /p\naccess:\n  - groups: [g]\n    admin: true\n", "ldap.base_dn"},
		{"ldap without service account", "data_dir: /tmp/x\nca:\n  organization: O\nldap:\n  url: ldaps://dc1.example.com\n  base_dn: DC=x\naccess:\n  - groups: [g]\n    admin: true\n", "bind_password_file"},
		{"ldap bad DN", "data_dir: /tmp/x\nca:\n  organization: O\nldap:\n  url: ldaps://dc1.example.com\n  base_dn: nonsense\n  bind_dn: CN=s,DC=x\n  bind_password_file: /p\naccess:\n  - groups: [g]\n    admin: true\n", "not a valid DN"},
		{"ldap filter without username", "data_dir: /tmp/x\nca:\n  organization: O\nldap:\n  url: ldaps://dc1.example.com\n  base_dn: DC=x\n  bind_dn: CN=s,DC=x\n  bind_password_file: /p\n  user_filter: (uid=alice)\naccess:\n  - groups: [g]\n    admin: true\n", "{username}"},
		{"ldap bad filter", "data_dir: /tmp/x\nca:\n  organization: O\nldap:\n  url: ldaps://dc1.example.com\n  base_dn: DC=x\n  bind_dn: CN=s,DC=x\n  bind_password_file: /p\n  user_filter: (uid={username}\naccess:\n  - groups: [g]\n    admin: true\n", "not a valid search filter"},
		{"ldap without access rules", "data_dir: /tmp/x\nca:\n  organization: O\nldap:\n  url: ldaps://dc1.example.com\n  base_dn: DC=x\n  bind_dn: CN=s,DC=x\n  bind_password_file: /p\n", "nobody may log in"},
		{"key passphrase inside data_dir", "data_dir: /tmp/x\nca:\n  organization: O\n  key_passphrase_file: /tmp/x/secret/pass\n", "must not be inside data_dir"},
		{"metrics token without address", "data_dir: /tmp/x\nca:\n  organization: O\nmetrics:\n  token_file: /t\n", "metrics.address is required"},
		{"metrics bad address", "data_dir: /tmp/x\nca:\n  organization: O\nmetrics:\n  address: localhost\n", "metrics.address must look like"},
		{"metrics on the server address", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  address: \":8443\"\nmetrics:\n  address: \":8443\"\n", "address of its own"},
		{"oidc both secrets", "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  url: https://ca.example.com\noidc:\n  issuer: https://login.example.com\n  client_id: id\n  client_secret: s\n  client_secret_file: /s\naccess:\n  - groups: [g]\n    admin: true\n", "not both"},
		{"acme resolver without port", "data_dir: /tmp/x\nca:\n  organization: O\nacme:\n  allowed_domains: [example.com]\n  dns_resolver: 10.0.0.53\n", "acme.dns_resolver must look like"},
		{"acme resolver without acme", "data_dir: /tmp/x\nca:\n  organization: O\nacme:\n  dns_resolver: 10.0.0.53:53\n", "ACME is off"},
		{"acme negative limit", "data_dir: /tmp/x\nca:\n  organization: O\nacme:\n  allowed_domains: [example.com]\n  limits:\n    orders_per_account_per_hour: -1\n", "0 (no limit) or more"},
		{"acme unknown limit", "data_dir: /tmp/x\nca:\n  organization: O\nacme:\n  allowed_domains: [example.com]\n  limits:\n    orders_per_hour: 5\n", "orders_per_hour"},
		{"acme unknown challenge", "data_dir: /tmp/x\nca:\n  organization: O\nacme:\n  allowed_domains: [example.com]\n  challenges: [http-01, dns]\n", "not a challenge type"},
		{"acme challenge twice", "data_dir: /tmp/x\nca:\n  organization: O\nacme:\n  allowed_domains: [example.com]\n  challenges: [dns-01, dns-01]\n", "listed twice"},
		{"constraint bad range", "data_dir: /tmp/x\nca:\n  organization: O\n  name_constraints:\n    ip_ranges: [10.0.0.0]\n", "not a range"},
		{"constraint wildcard", "data_dir: /tmp/x\nca:\n  organization: O\n  name_constraints:\n    dns_domains: [\"*.example.com\"]\n", "not a domain"},
		{"server name outside constraints", "data_dir: /tmp/x\nca:\n  organization: O\n  name_constraints:\n    dns_domains: [example.com]\nserver:\n  names: [ca.example.com, localhost]\n", "server.names"},
		{"acme domain outside constraints", "data_dir: /tmp/x\nca:\n  organization: O\n  name_constraints:\n    dns_domains: [example.com]\nserver:\n  names: [ca.example.com]\nacme:\n  allowed_domains: [other.com]\n", "acme.allowed_domains"},
		{"scep static without scep", "data_dir: /tmp/x\nca:\n  organization: O\nscep:\n  static:\n    challenge_file: /c\n", "SCEP is off"},
		{"scep static settings without file", "data_dir: /tmp/x\nca:\n  organization: O\nscep:\n  enabled: true\n  static:\n    x509: { cert_profile: tls-client }\n", "challenge_file is required"},
		{"scep static bad template", "data_dir: /tmp/x\nca:\n  organization: O\nscep:\n  enabled: true\n  static:\n    challenge_file: /c\n    x509: { cert_profile: ssh-user }\n", "no X.509 profile \"ssh-user\""},
		{"scep static server without domains", "data_dir: /tmp/x\nca:\n  organization: O\nscep:\n  enabled: true\n  static:\n    challenge_file: /c\n    x509: { cert_profile: tls-server }\n", "dns_domains is required"},
		{"scep static negative limit", "data_dir: /tmp/x\nca:\n  organization: O\nscep:\n  enabled: true\n  static:\n    challenge_file: /c\n    max_per_hour: -1\n", "0 (no limit) or more"},
		{"acme bad IP range", "data_dir: /tmp/x\nca:\n  organization: O\nacme:\n  allowed_ip_ranges: [10.0.0.0]\n", "acme.allowed_ip_ranges"},
		{"acme IP range outside constraints", "data_dir: /tmp/x\nca:\n  organization: O\n  name_constraints:\n    dns_domains: [localhost]\n    ip_ranges: [10.0.0.0/16, 127.0.0.0/8]\nacme:\n  allowed_ip_ranges: [10.0.0.0/8]\n", "outside ca.name_constraints"},
		{"bad key type", "data_dir: /tmp/x\nca:\n  organization: O\n  key_type: dsa\n", "ca.key_type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tt.content))
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// LDAP needs no server.url, and gets the Active Directory defaults.
func TestLoadLDAP(t *testing.T) {
	cfg, err := Load(writeConfig(t, "data_dir: /tmp/x\nca:\n  organization: O\nldap:\n  url: ldaps://dc1.corp.example.com\n  base_dn: DC=corp,DC=example,DC=com\n  bind_dn: CN=bastionxp-ca,OU=Service,DC=corp,DC=example,DC=com\n  bind_password_file: /etc/bastionxp-ca/ldap-password\naccess:\n  - groups: [linux-users]\n    ssh_principals: [\"{short_username}\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LDAP.UsernameAttribute != "userPrincipalName" || !strings.Contains(cfg.LDAP.UserFilter, "sAMAccountName={username}") ||
		!strings.Contains(cfg.LDAP.GroupFilter, "1.2.840.113556.1.4.1941") {
		t.Errorf("defaults = %+v, want Active Directory's", cfg.LDAP)
	}
}

// The example configuration in the repository loads.
func TestExampleConfigIsValid(t *testing.T) {
	if _, err := Load("../../bastionxp-ca.example.yaml"); err != nil {
		t.Fatalf("bastionxp-ca.example.yaml must stay loadable: %v", err)
	}
}

// The ACME allowed domains are read from the configuration.
func TestLoadACME(t *testing.T) {
	cfg, err := Load(writeConfig(t, "data_dir: /tmp/x\nca:\n  organization: O\nacme:\n  allowed_domains: [example.com, corp.internal]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ACME.AllowedDomains) != 2 || cfg.ACME.AllowedDomains[0] != "example.com" {
		t.Errorf("allowed domains = %v", cfg.ACME.AllowedDomains)
	}
}

// SCEP is on when enabled, and off unless configured.
func TestLoadSCEP(t *testing.T) {
	cfg, err := Load(writeConfig(t, "data_dir: /tmp/x\nca:\n  organization: O\nscep:\n  enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SCEP.Enabled {
		t.Error("scep.enabled = false, want true")
	}

	// Off unless switched on.
	cfg, err = Load(writeConfig(t, "data_dir: /tmp/x\nca:\n  organization: O\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SCEP.Enabled {
		t.Error("scep is on without being configured")
	}
}

// The public HTTP address and URL are read from the configuration.
func TestLoadPublicAddress(t *testing.T) {
	cfg, err := Load(writeConfig(t, "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  public_address: \":8080\"\n  public_url: http://ca.example.com:8080\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.PublicAddress != ":8080" || cfg.Server.PublicURL != "http://ca.example.com:8080" {
		t.Errorf("public address %q, public URL %q", cfg.Server.PublicAddress, cfg.Server.PublicURL)
	}
}

// OIDC settings and access rules are read, with the default claims and
// scopes; a provider on this machine may use plain HTTP, for tests.
func TestLoadOIDC(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
data_dir: /tmp/x
ca:
  organization: O
server:
  url: https://ca.example.com
oidc:
  issuer: https://login.microsoftonline.com/tenant/v2.0
  client_id: id
  client_secret: s
access:
  - groups: [linux-users]
    ssh_principals: ["{short_username}"]
  - users: [carol@corp.example.com]
    admin: true
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.UsernameClaim != "preferred_username" || cfg.OIDC.GroupsClaim != "groups" || len(cfg.OIDC.Scopes) != 3 {
		t.Errorf("defaults: %+v", cfg.OIDC)
	}
	if len(cfg.Access) != 2 || cfg.Access[0].SSHPrincipals[0] != "{short_username}" || !cfg.Access[1].Admin {
		t.Errorf("access = %+v", cfg.Access)
	}

	// A provider on this machine may use plain http, for tests.
	if _, err := Load(writeConfig(t, "data_dir: /tmp/x\nca:\n  organization: O\nserver:\n  url: https://ca\noidc:\n  issuer: http://127.0.0.1:5556\n  client_id: i\n  client_secret: s\naccess:\n  - groups: [g]\n    admin: true\n")); err != nil {
		t.Errorf("loopback http issuer: %v", err)
	}
}

// The ACME rate limits: defaults, one set alone, and zero for no limit.
func TestACMELimits(t *testing.T) {
	base := "data_dir: /tmp/x\nca:\n  organization: O\nacme:\n  allowed_domains: [example.com]\n"
	tests := []struct {
		name             string
		yaml             string
		accounts, orders int
	}{
		{"defaults", "", 100, 300},
		{"one set", "  limits:\n    accounts_per_ip_per_hour: 5\n", 5, 300},
		{"zero is no limit", "  limits:\n    orders_per_account_per_hour: 0\n", 100, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(writeConfig(t, base+tt.yaml))
			if err != nil {
				t.Fatal(err)
			}
			got := cfg.ACME.Limits.Resolved()
			if got.AccountsPerIP != tt.accounts || got.OrdersPerAccount != tt.orders {
				t.Errorf("limits = %+v, want %d accounts, %d orders", got, tt.accounts, tt.orders)
			}
		})
	}
}

// The root and intermediate lifetimes: 10 and 3 years by default, set in
// years or days; refused without a unit, not positive, above 30 years, with
// an unknown unit, below a year, or an intermediate that outlives the root.
func TestCALifetimes(t *testing.T) {
	const year = 365 * 24 * time.Hour
	base := "data_dir: /tmp/x\nca:\n  organization: Example Org\n"
	cfg, err := Load(writeConfig(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CA.RootLifetime() != 10*year || cfg.CA.IntermediateLifetime() != 3*year {
		t.Errorf("defaults: root %v, intermediate %v; want 10 and 3 years", cfg.CA.RootLifetime(), cfg.CA.IntermediateLifetime())
	}

	cfg, err = Load(writeConfig(t, base+"  root_validity: 20y\n  intermediate_validity: 1825d\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CA.RootLifetime() != 20*year || cfg.CA.IntermediateLifetime() != 5*year {
		t.Errorf("root %v, intermediate %v; want 20 and 5 years", cfg.CA.RootLifetime(), cfg.CA.IntermediateLifetime())
	}

	for _, bad := range []string{
		"  root_validity: 10\n",                              // no unit
		"  root_validity: 0y\n",                              // not positive
		"  root_validity: 31y\n",                             // above 30 years
		"  root_validity: 6m\n",                              // unknown unit
		"  intermediate_validity: 200d\n",                    // below a year
		"  root_validity: 2y\n",                              // the default intermediate (3y) outlives it
		"  root_validity: 5y\n  intermediate_validity: 6y\n", // longer than the root
	} {
		if _, err := Load(writeConfig(t, base+bad)); err == nil {
			t.Errorf("accepted:\n%s", bad)
		}
	}
}

// SCEP with a static password uses the tls-device profile by default, which
// logins may also hand out.
func TestSCEPStaticDefaultsToDeviceProfile(t *testing.T) {
	cfg, err := Load(writeConfig(t, "data_dir: /tmp/x\nca:\n  organization: O\nscep:\n  enabled: true\n  static:\n    challenge_file: /c\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.SCEP.Static.X509.CertProfile; got != "tls-device" {
		t.Errorf("cert_profile = %q, want tls-device", got)
	}
	// tls-device is a tls-client profile, so logins may hand it out.
	if _, err := cfg.checkX509Profile("oidc.x509.cert_profile", "tls-device", "tls-client"); err != nil {
		t.Errorf("tls-device refused as a login profile: %v", err)
	}
}
