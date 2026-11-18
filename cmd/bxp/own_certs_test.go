// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/bastionxp/bastionxp-ca/internal/config"
)

// After a login, a person gets a TLS client certificate for themselves:
// the CA decides the name, and it is theirs.
func TestOwnClientCertificateWithOIDC(t *testing.T) {
	testCA, idp := startOIDCTestCA(t)
	conn := testCA.oidcBrowser(t, idp, "Alice@Corp.Example.com", "linux-users")
	outDir := t.TempDir()

	if err := runTLS(context.Background(), io.Discard, conn, tlsOptions{outDir: outDir}); err != nil {
		t.Fatal(err)
	}
	name := "alice@corp.example.com"
	pair, err := tls.LoadX509KeyPair(filepath.Join(outDir, name+".crt"), filepath.Join(outDir, name+".key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	if leaf.Subject.CommonName != name || !slices.Equal(leaf.EmailAddresses, []string{name}) || len(leaf.DNSNames) != 0 {
		t.Errorf("CN %q, emails %v, DNS %v; want only %s", leaf.Subject.CommonName, leaf.EmailAddresses, leaf.DNSNames, name)
	}
	if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Errorf("usages %v, want client auth", leaf.ExtKeyUsage)
	}

	// Someone else's name, or a server certificate, needs an admin.
	for _, opts := range []tlsOptions{
		{outDir: t.TempDir(), names: []string{"bob@corp.example.com"}, template: "tls-client"},
		{outDir: t.TempDir(), names: []string{"web.example.com"}},
	} {
		conn := testCA.oidcBrowser(t, idp, "alice@corp.example.com", "linux-users") // one login each
		err := runTLS(context.Background(), io.Discard, conn, opts)
		if err == nil || !strings.Contains(err.Error(), "may only request") {
			t.Errorf("%v: error = %v, want a refusal", opts.names, err)
		}
	}
}

// The verifier's cert_profiles decide what people get: here a short-lived
// client certificate with an OU, and an SSH profile that restricts where
// it may be used from.
func TestLoginUsesTheVerifierProfiles(t *testing.T) {
	testCA := startTestCA(t, func(cfg *config.Config) {
		if err := yaml.Unmarshal([]byte(`
- { name: user-client, base: tls-client, validity: 7d, subject: { organizational_unit: [People] } }
- { name: ops-ssh, base: ssh-user, validity: 4h, ssh: { extensions: [permit-pty], critical_options: { source-address: 10.0.0.0/8 } } }
`), &cfg.Profiles); err != nil {
			t.Fatal(err)
		}
		cfg.OIDC.X509.CertProfile = "user-client"
		cfg.OIDC.SSH.CertProfile = "ops-ssh"
	})
	conn := testCA.oidcBrowser(t, testCA.idp, "alice@corp.example.com", "linux-users")

	outDir := t.TempDir()
	if err := runTLS(context.Background(), io.Discard, conn, tlsOptions{outDir: outDir}); err != nil {
		t.Fatal(err)
	}
	leaf, err := readLeaf(filepath.Join(outDir, "alice@corp.example.com.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if lifetime := leaf.NotAfter.Sub(leaf.NotBefore).Round(time.Hour); lifetime != 7*24*time.Hour {
		t.Errorf("lifetime %v, want the profile's 7 days", lifetime)
	}
	if !slices.Equal(leaf.Subject.OrganizationalUnit, []string{"People"}) {
		t.Errorf("OU %v, want the profile's", leaf.Subject.OrganizationalUnit)
	}

	conn = testCA.oidcBrowser(t, testCA.idp, "alice@corp.example.com", "linux-users")
	keyFile := writeSSHKey(t, t.TempDir())
	if err := runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: keyFile}); err != nil {
		t.Fatal(err)
	}
	cert := sshCertAt(t, keyFile)
	if cert.CriticalOptions["source-address"] != "10.0.0.0/8" || len(cert.Extensions) != 1 {
		t.Errorf("critical options %v, extensions %v; want the profile's", cert.CriticalOptions, cert.Extensions)
	}
	if lifetime := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second; lifetime.Round(time.Hour) != 4*time.Hour {
		t.Errorf("lifetime %v, want the profile's 4 hours", lifetime)
	}
}

// The same with a directory login: the profile comes from the ldap
// verifier, chosen by the CA, not by the command.
func TestOwnCertificatesWithLDAP(t *testing.T) {
	testCA := startLDAPTestCA(t)
	outDir := t.TempDir()
	if err := runTLS(context.Background(), io.Discard, testCA.ldapUser("alice", "alice-pw"), tlsOptions{outDir: outDir}); err != nil {
		t.Fatal(err)
	}
	leaf, err := readLeaf(filepath.Join(outDir, "alice@corp.example.com.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "alice@corp.example.com" {
		t.Errorf("CN %q", leaf.Subject.CommonName)
	}
	keyFile := writeSSHKey(t, t.TempDir())
	if err := runSSH(context.Background(), io.Discard, testCA.ldapUser("alice", "alice-pw"), sshOptions{keyFile: keyFile}); err != nil {
		t.Fatalf("SSH without --profile: %v", err)
	}
}
