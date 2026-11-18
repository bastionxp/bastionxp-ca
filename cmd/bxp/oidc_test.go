// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/config"
	"github.com/bastionxp/bastionxp-ca/internal/oidc/oidctest"
)

// startOIDCTestCA starts a test CA (startTestCA has the browser login and
// the group rules) and returns its fake identity provider.
func startOIDCTestCA(t *testing.T) (*testCA, *oidctest.Fake) {
	t.Helper()
	testCA := startTestCA(t)
	return testCA, testCA.idp
}

// oidcBrowser returns connection settings for a person whose browser is
// logged in at the company's provider.
func (c *testCA) oidcBrowser(t *testing.T, idp *oidctest.Fake, username string, groups ...string) connection {
	t.Helper()
	idp.SignInAs(username, groups...)
	browser := newTestBrowser(t, c.root)
	return connection{url: c.url, root: c.root, prompt: io.Discard, openBrowser: browser.open}
}

func sshCertAt(t *testing.T, keyFile string) *ssh.Certificate {
	t.Helper()
	return readSSHCert(t, strings.TrimSuffix(keyFile, ".pub")+"-cert.pub")
}

// With an identity provider set up, "bxp ssh" logs in there by itself.
func TestSSHWithOIDCLogin(t *testing.T) {
	testCA, idp := startOIDCTestCA(t)
	conn := testCA.oidcBrowser(t, idp, "Alice@Corp.Example.com", "linux-users")

	keyFile := writeSSHKey(t, t.TempDir())
	if err := runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: keyFile, template: "ssh-user"}); err != nil {
		t.Fatal(err)
	}
	cert := sshCertAt(t, keyFile)
	if strings.Join(cert.ValidPrincipals, ",") != "alice" {
		t.Errorf("principals = %v, want [alice] from {short_username}", cert.ValidPrincipals)
	}
	if !strings.HasPrefix(cert.KeyId, "alice@corp.example.com-") {
		t.Errorf("key ID = %q, want the company account", cert.KeyId)
	}
}

// bxp ssh through an OIDC login by someone in no matching group is refused.
func TestOIDCPersonWithoutAMatchingGroup(t *testing.T) {
	testCA, idp := startOIDCTestCA(t)
	conn := testCA.oidcBrowser(t, idp, "eve@corp.example.com", "marketing")

	keyFile := writeSSHKey(t, t.TempDir())
	err := runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: keyFile, template: "ssh-user"})
	if err == nil || !strings.Contains(err.Error(), "may not use this CA") {
		t.Errorf("error = %v, want a refusal", err)
	}
}

// An admin by group gets a token for a server from their own machine.
func TestRemoteTokenWithOIDCAdmin(t *testing.T) {
	testCA, idp := startOIDCTestCA(t)
	t.Setenv(envClientDir, t.TempDir())
	conn := testCA.oidcBrowser(t, idp, "carol@corp.example.com", "ca-admins")

	var out bytes.Buffer
	opts := tokenOptions{template: "ssh-host", names: []string{"web1.example.com"}, validFor: time.Hour}
	if err := runRemoteToken(context.Background(), &out, conn, opts); err != nil {
		t.Fatal(err)
	}
	server := connection{url: testCA.url, root: testCA.root, token: strings.TrimSpace(out.String()), prompt: io.Discard}
	keyFile := writeSSHKey(t, t.TempDir())
	if err := runSSH(context.Background(), io.Discard, server, sshOptions{keyFile: keyFile}); err != nil {
		t.Fatal(err)
	}
	if cert := sshCertAt(t, keyFile); cert.CertType != ssh.HostCert {
		t.Errorf("certificate type = %d, want a host certificate", cert.CertType)
	}
}

// The client secret can come from a file, so the configuration holds none.
func TestOIDCClientSecretFile(t *testing.T) {
	var secretFile string
	testCA := startTestCA(t, func(cfg *config.Config) {
		secretFile = writeSecret(t, cfg.OIDC.ClientSecret+"\n")
		cfg.OIDC.ClientSecret = ""
		cfg.OIDC.ClientSecretFile = secretFile
	})
	conn := testCA.oidcBrowser(t, testCA.idp, "alice@corp.example.com", "linux-users")
	keyFile := writeSSHKey(t, t.TempDir())
	if err := runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: keyFile, template: "ssh-user"}); err != nil {
		t.Fatal(err)
	}
}
