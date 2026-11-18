// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const base = "data_dir: /tmp/x\nca:\n  organization: O\n"

// Custom X.509 profiles are read with their lifetime, subject rules, names,
// policies, extensions and key rules, and can be based on email for S/MIME;
// the built-in profiles remain.
func TestProfile(t *testing.T) {
	cfg, err := Load(writeConfig(t, base+`profiles:
  - name: device-client
    base: tls-client
    validity: 365d
    subject: { organizational_unit: [Devices], require_common_name: true }
    names: { email: true }
    policies: [1.3.6.1.4.1.55555.1]
    extensions:
      - { oid: 1.3.6.1.4.1.55555.2, value_hex: "0c03616263" }
    keys: { algorithms: [rsa], min_rsa_bits: 3072 }
  - name: smime
    base: email
scep:
  enabled: true
  static: { challenge_file: /c, x509: { cert_profile: device-client } }
`))
	if err != nil {
		t.Fatal(err)
	}
	deviceClient, ok := cfg.X509Template("device-client")
	if !ok {
		t.Fatal("no device-client template")
	}
	if deviceClient.DefaultValidity != 365*24*time.Hour || deviceClient.MaxValidity < deviceClient.DefaultValidity {
		t.Errorf("validity %s, max %s", deviceClient.DefaultValidity, deviceClient.MaxValidity)
	}
	if len(deviceClient.ExtKeyUsage) != 1 || deviceClient.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || deviceClient.RequireHostName {
		t.Errorf("ext key usage %v, host name %v", deviceClient.ExtKeyUsage, deviceClient.RequireHostName)
	}
	if deviceClient.Names == nil || deviceClient.Names.DNS || !deviceClient.Names.Email || !deviceClient.RequireCommonName ||
		len(deviceClient.Policies) != 1 || len(deviceClient.Extensions) != 1 || deviceClient.Keys.MinRSABits != 3072 {
		t.Errorf("template = %+v", deviceClient)
	}
	if smime, _ := cfg.X509Template("smime"); smime.ExtKeyUsage[0] != x509.ExtKeyUsageEmailProtection {
		t.Errorf("smime: %v", smime.ExtKeyUsage)
	}
	// The built-ins are still there.
	if _, ok := cfg.X509Template("tls-server"); !ok {
		t.Error("tls-server is gone")
	}
}

// Invalid X.509 profiles are refused, each with its message: bad or taken
// names, an unknown base, bad lifetimes, unknown key usages, extensions the
// CA sets itself or that are not one DER value in hex, bad policy OIDs,
// wildcards or email without a host name where not allowed, and bad key
// rules; a name used twice.
func TestProfileRefusals(t *testing.T) {
	for want, profile := range map[string]string{
		"lower case letters":       "{ name: DeviceClient, base: tls-client }",
		"taken by a built-in":      "{ name: tls-server, base: tls-client }",
		"base must be one of":      "{ name: x, base: device }",
		"not a lifetime":           "{ name: x, base: tls-client, validity: a-year }",
		"out of range":             "{ name: x, base: tls-client, validity: 20000d }",
		"longer than max_validity": "{ name: x, base: tls-client, validity: 30d, max_validity: 1d }",
		"ext_key_usage: unknown":   "{ name: x, base: tls-client, ext_key_usage: [smartcard] }",
		"key_usage: unknown":       "{ name: x, base: tls-client, key_usage: [sign] }",
		"set by the CA itself":     `{ name: x, base: tls-client, extensions: [{ oid: 2.5.29.17, value_hex: "3000" }] }`,
		"is not hex":               `{ name: x, base: tls-client, extensions: [{ oid: 1.2.3.4, value_hex: "zz" }] }`,
		"not one DER value":        `{ name: x, base: tls-client, extensions: [{ oid: 1.2.3.4, value_hex: "0c" }] }`,
		"not an OID":               "{ name: x, base: tls-client, policies: [hello] }",
		"wildcard needs":           "{ name: x, base: tls-client, names: { wildcard: true } }",
		"needs a host name":        "{ name: x, base: tls-server, names: { email: true } }",
		"keys.algorithms: unknown": "{ name: x, base: tls-client, keys: { algorithms: [dsa] } }",
		"keys.curves: unknown":     "{ name: x, base: tls-client, keys: { curves: [secp256k1] } }",
		"between 2048 and 8192":    "{ name: x, base: tls-client, keys: { min_rsa_bits: 1024 } }",
	} {
		_, err := Load(writeConfig(t, base+"profiles:\n  - "+profile+"\n"))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error = %v, want %q", profile, err, want)
		}
	}
	_, err := Load(writeConfig(t, base+"profiles:\n  - { name: x, base: tls-client }\n  - { name: x, base: email }\n"))
	if err == nil || !strings.Contains(err.Error(), "used twice") {
		t.Errorf("duplicate: %v", err)
	}
}

// Custom SSH profiles are read with their lifetime, extensions (an empty
// list meaning none) and critical options, for users and hosts; unknown
// extensions or options, a bad source-address, options on a host profile,
// X.509 settings on SSH and the reverse, and the ssh- name prefix are
// refused.
func TestSSHProfiles(t *testing.T) {
	base := "data_dir: /tmp/x\nca:\n  organization: O\nprofiles:\n"
	cfg, err := Load(writeConfig(t, base+`  - name: ops-ssh
    base: ssh-user
    validity: 8h
    max_validity: 24h
    ssh:
      extensions: [permit-pty, permit-agent-forwarding]
      critical_options: { source-address: "10.0.0.0/8,192.168.1.5", force-command: /usr/bin/backup }
  - name: locked
    base: ssh-user
    ssh: { extensions: [] }
  - name: web-hosts
    base: ssh-host
    validity: 90d
`))
	if err != nil {
		t.Fatal(err)
	}
	ops, ok := cfg.SSHTemplate("ops-ssh")
	if !ok || ops.Base != "ssh-user" || ops.DefaultValidity != 8*time.Hour || ops.MaxValidity != 24*time.Hour {
		t.Fatalf("ops-ssh = %+v", ops)
	}
	if len(ops.Extensions) != 2 || ops.CriticalOptions["source-address"] != "10.0.0.0/8,192.168.1.5" || ops.CriticalOptions["force-command"] != "/usr/bin/backup" {
		t.Errorf("ops-ssh extensions %v, critical options %v", ops.Extensions, ops.CriticalOptions)
	}
	if locked, _ := cfg.SSHTemplate("locked"); len(locked.Extensions) != 0 {
		t.Errorf("an empty extensions list gives %v, want none", locked.Extensions)
	}
	if hosts, _ := cfg.SSHTemplate("web-hosts"); hosts.CertType != ssh.HostCert || hosts.DefaultValidity != 90*24*time.Hour {
		t.Errorf("web-hosts = %+v", hosts)
	}
	if _, isX509 := cfg.X509Template("ops-ssh"); isX509 {
		t.Error("an SSH profile is listed as an X.509 one")
	}

	for name, bad := range map[string]string{
		"unknown extension":         "  - { name: p, base: ssh-user, ssh: { extensions: [permit-everything] } }\n",
		"unknown critical option":   "  - { name: p, base: ssh-user, ssh: { critical_options: { no-logout: x } } }\n",
		"bad source-address":        "  - { name: p, base: ssh-user, ssh: { critical_options: { source-address: not-an-address } } }\n",
		"host profile with options": "  - { name: p, base: ssh-host, ssh: { critical_options: { force-command: x } } }\n",
		"X.509 setting on SSH":      "  - { name: p, base: ssh-user, ext_key_usage: [client_auth] }\n",
		"ssh block on X.509":        "  - { name: p, base: tls-client, ssh: { extensions: [permit-pty] } }\n",
		"ssh- prefix":               "  - { name: ssh-ops, base: ssh-user }\n",
	} {
		if _, err := Load(writeConfig(t, base+bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Each verifier's cert_profile must be of the right kind.
func TestVerifierCertProfiles(t *testing.T) {
	base := `data_dir: /tmp/x
ca: { organization: O }
server: { url: "https://ca.example.com" }
access: [ { groups: [g], ssh_principals: [x] } ]
profiles:
  - { name: user-client, base: tls-client }
  - { name: short-server, base: tls-server, validity: 7d }
  - { name: ops-ssh, base: ssh-user }
  - { name: web-hosts, base: ssh-host }
oidc: { issuer: "https://idp.example.com", client_id: c, client_secret: s`
	good := base + `, x509: { cert_profile: user-client }, ssh: { cert_profile: ops-ssh } }
acme: { allowed_domains: [example.com], x509: { cert_profile: short-server } }
`
	if _, err := Load(writeConfig(t, good)); err != nil {
		t.Fatalf("good profiles refused: %v", err)
	}
	if _, err := Load(writeConfig(t, base+" }\n")); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
	for name, bad := range map[string]string{
		"oidc x509 server":   base + `, x509: { cert_profile: short-server } }` + "\n",
		"oidc ssh host":      base + `, ssh: { cert_profile: web-hosts } }` + "\n",
		"oidc x509 unknown":  base + `, x509: { cert_profile: nothing } }` + "\n",
		"acme client":        base + " }\nacme: { allowed_domains: [example.com], x509: { cert_profile: user-client } }\n",
		"acme x509 when off": base + " }\nacme: { x509: { cert_profile: tls-server } }\n",
	} {
		if _, err := Load(writeConfig(t, bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
