// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path"
	"regexp"
)

// A feature is one chapter of the test specification.
type feature struct {
	Code  string // short name, used in the rules
	Title string
	Page  string // the page in docs/testing/
}

// features, in the order of the specification.
var features = []feature{
	{"CA", "CA creation and hierarchy", "ca.md"},
	{"KEYS", "Key protection", "key-protection.md"},
	{"PROF", "Certificate profiles", "profiles.md"},
	{"TOK", "One-time tokens", "tokens.md"},
	{"TLS", "TLS certificates", "tls.md"},
	{"SSH", "SSH certificates", "ssh.md"},
	{"RENEW", "Renewal", "renewal.md"},
	{"REV", "Revocation, CRL and OCSP", "revocation.md"},
	{"ACME", "ACME", "acme.md"},
	{"SCEP", "SCEP", "scep.md"},
	{"OIDC", "OIDC login", "oidc.md"},
	{"LDAP", "LDAP login", "ldap.md"},
	{"ACCESS", "Access rules", "access-rules.md"},
	{"CFG", "Configuration and reload", "configuration.md"},
	{"STORE", "Database and backup", "storage.md"},
	{"CLI", "Client connection and trust", "client.md"},
	{"OPS", "Operations: server, diagnostics, metrics, logs", "operations.md"},
}

// A rule gives a feature to tests: those in a package (and file, if
// given) whose name matches (any name, if Name is empty).
type rule struct {
	Pkg, File, Name, Feature string
}

// rules, the first that matches wins: put the specific ones first.
var rules = []rule{
	// End-to-end tests of the binary, by name.
	{"test/e2e", "", "^TestCommandLine$", "CLI"},
	{"test/e2e", "", "^TestClientErrors$", "CLI"},
	{"test/e2e", "", "^TestTLSAndRevocation$", "REV"},
	{"test/e2e", "", "^TestTLSHandshake$", "TLS"},
	{"test/e2e", "", "^TestSSHHostRenew$", "RENEW"},
	{"test/e2e", "", "^TestRenew$", "RENEW"},
	{"test/e2e", "", "^Test(SSH|OpenSSHLogin|NewSSHUserCA|SSHAgent)$", "SSH"},
	{"test/e2e", "", "^Test(NewIntermediate|ExternalRoot)$", "CA"},
	{"test/e2e", "", "^TestEncryptedServerKeys$", "KEYS"},
	{"test/e2e", "", "^Test(BackupAndRestore|ConcurrentProcesses)$", "STORE"},
	{"test/e2e", "", "^TestTokenLimits$", "TOK"},
	{"test/e2e", "", "^TestReloadApplies$", "CFG"},
	{"test/e2e", "", "^Test(ACME|FakeDNS|Autocert|Caddy)", "ACME"},
	{"test/kubernetes", "", "^TestCertManager$", "ACME"},
	{"test/e2e", "", "^TestSCEP", "SCEP"},
	{"test/e2e", "", "", "OPS"},

	// The command line, by file, then by name where a file mixes features.
	{"cmd/bxp", "client_test.go", "^TestTLS", "TLS"},
	{"cmd/bxp", "client_test.go", "^Test(SSH|TokenSubject)", "SSH"},
	{"cmd/bxp", "client_test.go", "", "CLI"},
	{"cmd/bxp", "serve_test.go", "^TestServeNeeds", "OPS"},
	{"cmd/bxp", "serve_test.go", "^TestNoGetCommand$", "CLI"},
	{"cmd/bxp", "serve_test.go", "", "TOK"},
	{"cmd/bxp", "access_test.go", "", "ACCESS"},
	{"cmd/bxp", "own_certs_test.go", "", "ACCESS"},
	{"cmd/bxp", "acme_*", "", "ACME"},
	{"cmd/bxp", "agent_test.go", "", "SSH"},
	{"cmd/bxp", "sshca_test.go", "", "SSH"},
	{"cmd/bxp", "backup_test.go", "", "STORE"},
	{"cmd/bxp", "schema_test.go", "", "STORE"},
	{"cmd/bxp", "browser_test.go", "", "OIDC"},
	{"cmd/bxp", "oidc_test.go", "", "OIDC"},
	{"cmd/bxp", "keycloak_test.go", "", "OIDC"},
	{"cmd/bxp", "ldap_test.go", "", "LDAP"},
	{"cmd/bxp", "constraints_test.go", "", "CA"},
	{"cmd/bxp", "external_test.go", "", "CA"},
	{"cmd/bxp", "fingerprint_test.go", "", "CA"},
	{"cmd/bxp", "init_output_test.go", "", "CA"},
	{"cmd/bxp", "intermediate_test.go", "", "CA"},
	{"cmd/bxp", "lifetime_test.go", "", "CA"},
	{"cmd/bxp", "keys_test.go", "", "KEYS"},
	{"cmd/bxp", "passphrase_test.go", "", "KEYS"},
	{"cmd/bxp", "profiles_test.go", "", "PROF"},
	{"cmd/bxp", "reload*", "", "CFG"},
	{"cmd/bxp", "renew_test.go", "", "RENEW"},
	{"cmd/bxp", "revoke_test.go", "", "REV"},
	{"cmd/bxp", "scep*", "", "SCEP"},
	{"cmd/bxp", "tls_names_test.go", "", "TLS"},
	{"cmd/bxp", "trust_test.go", "", "CLI"},
	{"cmd/bxp", "main_test.go", "", "CLI"},
	{"cmd/bxp", "doctor_test.go", "", "OPS"},
	{"cmd/bxp", "report_test.go", "", "OPS"},
	{"cmd/bxp", "metrics_test.go", "", "OPS"},
	{"cmd/bxp", "logging_test.go", "", "OPS"},
	{"cmd/bxp", "list_test.go", "", "OPS"},
	{"cmd/bxp", "version_test.go", "", "OPS"},

	// The packages below cmd/bxp.
	{"internal/acme", "", "", "ACME"},
	{"internal/ca", "encrypted_test.go", "", "KEYS"},
	{"internal/ca", "profiles_test.go", "", "PROF"},
	{"internal/ca", "revocation_test.go", "", "REV"},
	{"internal/ca", "ssh*", "", "SSH"},
	{"internal/ca", "x509_test.go", "", "TLS"},
	{"internal/ca", "", "", "CA"},
	{"internal/client", "", "", "CLI"},
	{"internal/config", "profiles_test.go", "", "PROF"},
	{"internal/config", "", "", "CFG"},
	{"internal/keyfile", "", "", "KEYS"},
	{"internal/ldap", "", "", "LDAP"},
	{"internal/metrics", "", "", "OPS"},
	{"internal/oidc", "", "", "OIDC"},
	{"internal/policy", "access_test.go", "", "ACCESS"},
	{"internal/policy", "", "^(TestCheckX509|TestCheckSSH)", "TOK"},
	{"internal/policy", "", "", "ACME"},
	{"internal/scep", "", "", "SCEP"},
	{"internal/server", "", "^FuzzOCSP$", "REV"},
	{"internal/server", "", "^FuzzCSR$", "TLS"},
	{"internal/server", "", "^FuzzRenew$", "RENEW"},
	{"internal/server", "ldap_login_test.go", "", "LDAP"},
	{"internal/server", "login_flow_test.go", "", "OIDC"},
	{"internal/server", "oidc_test.go", "", "OIDC"},
	{"internal/server", "public_test.go", "", "REV"},
	{"internal/server", "revcache_test.go", "", "REV"},
	{"internal/server", "renew_test.go", "", "RENEW"},
	{"internal/server", "scep*", "", "SCEP"},
	{"internal/server", "server_test.go", "^Test(Health|UnknownRoutes)$", "OPS"},
	{"internal/server", "server_test.go", "", "TLS"},
	{"internal/server", "ssh_test.go", "", "SSH"},
	{"internal/server", "tls_test.go", "", "TLS"},
	{"internal/store", "", "", "STORE"},
	{"internal/token", "", "", "TOK"},
}

// featureOf is the feature of a test case, or "" if no rule fits.
func featureOf(c testCase) string {
	for _, r := range rules {
		if r.Pkg != c.Pkg {
			continue
		}
		if r.File != "" {
			if ok, _ := path.Match(r.File, c.File); !ok {
				continue
			}
		}
		if r.Name != "" && !regexp.MustCompile(r.Name).MatchString(c.Name) {
			continue
		}
		return r.Feature
	}
	return ""
}
