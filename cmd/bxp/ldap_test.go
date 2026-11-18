// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/config"
	"github.com/bastionxp/bastionxp-ca/internal/ldap/ldaptest"
)

// startLDAPTestCA starts a test CA that also checks passwords against a
// fake Active Directory: alice is in linux-users, carol in ca-admins.
func startLDAPTestCA(t *testing.T) *testCA {
	t.Helper()
	dir := ldaptest.NewFake()
	t.Cleanup(dir.Close)
	aliceDN := "CN=Alice,OU=People,DC=corp,DC=example,DC=com"
	carolDN := "CN=Carol,OU=People,DC=corp,DC=example,DC=com"
	dir.AddUser(ldaptest.User{DN: aliceDN, SAM: "alice", UPN: "alice@corp.example.com", Password: "alice-pw"})
	dir.AddUser(ldaptest.User{DN: carolDN, SAM: "carol", UPN: "carol@corp.example.com", Password: "carol-pw"})
	dir.AddGroup(ldaptest.Group{DN: "CN=linux-users,OU=Groups,DC=corp,DC=example,DC=com", Members: []string{aliceDN}})
	dir.AddGroup(ldaptest.Group{DN: "CN=ca-admins,OU=Groups,DC=corp,DC=example,DC=com", Members: []string{carolDN}})

	files := t.TempDir()
	caFile := filepath.Join(files, "ad-root.pem")
	passwordFile := filepath.Join(files, "ldap-password")
	if err := os.WriteFile(caFile, dir.CertPEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	// With a line end, as an editor would save it.
	if err := os.WriteFile(passwordFile, []byte(ldaptest.ServicePassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return startTestCA(t, func(cfg *config.Config) {
		cfg.LDAP = config.LDAP{
			URL: dir.URL(), CAFile: caFile,
			BaseDN: ldaptest.BaseDN, BindDN: ldaptest.ServiceDN, BindPasswordFile: passwordFile,
			GroupBaseDN: ldaptest.GroupBaseDN,
		}
		// What Load would fill in.
		cfg.LDAP.UserFilter = "(&(objectClass=user)(sAMAccountName={username}))"
		cfg.LDAP.UsernameAttribute = "userPrincipalName"
		cfg.LDAP.GroupFilter = "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={user_dn}))"
	})
}

// ldapUser returns connection settings for a person who logs in with
// their directory password.
func (c *testCA) ldapUser(username, password string) connection {
	return connection{
		url: c.url, root: c.root, prompt: io.Discard,
		ldap: true, ldapUser: username,
		readPassword: func(string) (string, error) { return password, nil },
	}
}

// bxp ssh with an LDAP login gets a valid certificate for the user's
// principal, with the username in the key ID.
func TestSSHWithLDAPLogin(t *testing.T) {
	testCA := startLDAPTestCA(t)
	keyFile := writeSSHKey(t, t.TempDir())
	if err := runSSH(context.Background(), io.Discard, testCA.ldapUser("alice", "alice-pw"), sshOptions{keyFile: keyFile, template: "ssh-user"}); err != nil {
		t.Fatal(err)
	}
	cert := sshCertAt(t, keyFile)
	if !slices.Equal(cert.ValidPrincipals, []string{"alice"}) || !strings.HasPrefix(cert.KeyId, "alice@corp.example.com-") {
		t.Errorf("principals %v, key ID %q", cert.ValidPrincipals, cert.KeyId)
	}
	if time.Until(time.Unix(int64(cert.ValidBefore), 0)) <= 0 {
		t.Error("the certificate is not valid")
	}
}

// bxp ssh with a wrong LDAP password fails with the CA's refusal.
func TestSSHWithWrongLDAPPassword(t *testing.T) {
	testCA := startLDAPTestCA(t)
	keyFile := writeSSHKey(t, t.TempDir())
	err := runSSH(context.Background(), io.Discard, testCA.ldapUser("alice", "wrong"), sshOptions{keyFile: keyFile, template: "ssh-user"})
	if err == nil || !strings.Contains(err.Error(), "invalid username or password") {
		t.Errorf("error = %v, want a refused login", err)
	}
}

// An admin by AD group gets a token for a server from their own machine.
func TestRemoteTokenWithLDAPAdmin(t *testing.T) {
	testCA := startLDAPTestCA(t)
	t.Setenv(envClientDir, t.TempDir())

	var out bytes.Buffer
	opts := tokenOptions{template: "ssh-host", names: []string{"web1.example.com"}, validFor: time.Hour}
	if err := runRemoteToken(context.Background(), &out, testCA.ldapUser("carol", "carol-pw"), opts); err != nil {
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

// bxp ssh with an LDAP login against a CA without LDAP says it is not set
// up.
func TestLDAPLoginNotSetUp(t *testing.T) {
	testCA := startTestCA(t)
	keyFile := writeSSHKey(t, t.TempDir())
	err := runSSH(context.Background(), io.Discard, testCA.ldapUser("alice", "alice-pw"), sshOptions{keyFile: keyFile, template: "ssh-user"})
	if err == nil || !strings.Contains(err.Error(), "not set up") {
		t.Errorf("error = %v, want 'not set up'", err)
	}
}

// --ldap and --token together, and --ldap-user or --password-stdin without
// --ldap, are refused.
func TestLoginFlagsThatDoNotGoTogether(t *testing.T) {
	for _, conn := range []connection{
		{ldap: true, token: "x"},
		{ldapUser: "alice"},
		{passwordStdin: true},
	} {
		if err := conn.checkLoginFlags(); err == nil {
			t.Errorf("%+v: no error", conn)
		}
	}
	if err := (connection{ldap: true, ldapUser: "alice", passwordStdin: true}).checkLoginFlags(); err != nil {
		t.Error(err)
	}
}

// The LDAP settings are refused with a missing or empty bind password file,
// a missing CA file, or a CA file without a PEM certificate.
func TestLDAPClientNeedsItsFiles(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	notPEM := filepath.Join(dir, "not-pem")
	password := filepath.Join(dir, "password")
	for file, content := range map[string]string{empty: "\n", notPEM: "hello", password: "pw"} {
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	base := config.LDAP{URL: "ldaps://dc1.example.com", BaseDN: "DC=x", BindDN: "CN=s,DC=x"}
	tests := []struct {
		name             string
		passwordFile, ca string
		want             string
	}{
		{"missing password file", filepath.Join(dir, "nope"), "", "bind_password_file"},
		{"empty password file", empty, "", "is empty"},
		{"missing CA file", password, filepath.Join(dir, "nope"), "ca_file"},
		{"CA file without PEM", password, notPEM, "no PEM certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			cfg.BindPasswordFile, cfg.CAFile = tt.passwordFile, tt.ca
			if _, err := newLDAPClient(cfg); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

// A change to the LDAP settings is reported as needing a restart, not a
// reload.
func TestLDAPChangeNeedsRestart(t *testing.T) {
	running := &config.Config{LDAP: config.LDAP{URL: "ldaps://dc1.example.com"}}
	next := &config.Config{LDAP: config.LDAP{URL: "ldaps://dc2.example.com"}}
	if changed := needsRestart(running, next); !slices.Contains(changed, "ldap") {
		t.Errorf("changed = %v, want ldap", changed)
	}
}

// With --password-stdin, the first line of the standard input is the
// password, as in: cat ~/.ad-password | bxp ssh --ldap --password-stdin ...
func TestPasswordFromStdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString("s3cret pass\r\nignored\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	stdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = stdin; r.Close() })

	got, err := connection{ldap: true, passwordStdin: true}.password("alice")
	if err != nil || got != "s3cret pass" {
		t.Errorf("password = %q, %v", got, err)
	}
}
