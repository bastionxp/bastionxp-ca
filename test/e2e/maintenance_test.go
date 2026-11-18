// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && !windows

package e2e

import (
	"bytes"
	"crypto/x509"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// The operations an administrator runs rarely, and then under pressure:
// a new intermediate, a CA under a company root, a new SSH CA key, and a
// restore from backup.

// opensslVerify checks with openssl that the first certificate in certFile
// chains to root, through the other certificates given.
func opensslVerify(t *testing.T, root, certFile string, untrusted ...string) bool {
	t.Helper()
	leaf := filepath.Join(t.TempDir(), "leaf.pem")
	writeCert(t, leaf, readCerts(t, certFile)[0])
	args := []string{"verify", "-CAfile", root}
	for _, u := range untrusted {
		args = append(args, "-untrusted", u)
	}
	r := run(t, t.TempDir(), nil, tool(t, "openssl"), append(args, leaf)...)
	return r.code == 0 && strings.Contains(r.stdout, ": OK")
}

// issueTLS gets a tls-server certificate with a token, and returns the
// certificate file and the key file.
func (c *testCA) issueTLS(name string) (certFile, keyFile string) {
	c.t.Helper()
	out := c.t.TempDir()
	c.client("tls", "--token", c.token("tls-server", name), "--name", name, "--out-dir", out)
	return filepath.Join(out, name+".crt"), filepath.Join(out, name+".key")
}

// A new intermediate, made with the root key from offline storage: after
// a restart new certificates come from it, old ones still verify, and
// renewing an old one moves it over.
func TestNewIntermediate(t *testing.T) {
	c := newCA(t, "")
	c.start()
	c.trust()
	oldCert, oldKey := c.issueTLS("old.e2e.localhost")
	oldIntermediate := filepath.Join(t.TempDir(), "old-intermediate.crt")
	writeFile(t, oldIntermediate, string(readFile(t, filepath.Join(c.dataDir, "intermediate.crt"))))
	if err := c.stop(); err != nil {
		t.Fatal(err)
	}

	// The root key goes offline, as the docs advise.
	offline := filepath.Join(t.TempDir(), "root.key")
	if err := os.Rename(filepath.Join(c.dataDir, "root.key"), offline); err != nil {
		t.Fatal(err)
	}
	c.admin("new-intermediate", "--root-key", offline,
		"--root-passphrase-file", filepath.Join(c.dir, "root-passphrase"), "--yes")
	newIntermediate := readCerts(t, filepath.Join(c.dataDir, "intermediate.crt"))[0]
	if bytes.Equal(newIntermediate.SubjectKeyId, readCerts(t, oldIntermediate)[0].SubjectKeyId) {
		t.Fatal("the intermediate did not change")
	}

	c.logs = &syncBuffer{}
	c.start()
	newCert, _ := c.issueTLS("new.e2e.localhost")
	if issuer := readCerts(t, newCert)[0].AuthorityKeyId; !bytes.Equal(issuer, newIntermediate.SubjectKeyId) {
		t.Error("a new certificate is not issued by the new intermediate")
	}
	if !opensslVerify(t, c.root, newCert, filepath.Join(c.dataDir, "intermediate.crt")) {
		t.Error("openssl does not verify a certificate from the new intermediate")
	}
	if !opensslVerify(t, c.root, oldCert, oldIntermediate) {
		t.Error("a certificate from the old intermediate no longer verifies")
	}

	// Renewing moves an old certificate to the new intermediate.
	c.client("renew", "--cert", oldCert, "--key", oldKey, "--force")
	if issuer := readCerts(t, oldCert)[0].AuthorityKeyId; !bytes.Equal(issuer, newIntermediate.SubjectKeyId) {
		t.Error("renewal did not move the certificate to the new intermediate")
	}
}

// A CA under a company's root, two levels up, played by openssl: a root
// and an issuing CA. The CSR from "bxp init --external-root" is signed by
// the issuing CA; after the import the CA issues certificates that verify
// against the company root, from what clients are sent.
func TestExternalRoot(t *testing.T) {
	openssl := tool(t, "openssl")
	c := newCAWith(t, caOptions{externalRoot: true})
	corp := t.TempDir()
	in := func(name string) string { return filepath.Join(corp, name) }
	writeFile(t, in("ca.ext"), "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign,digitalSignature\n"+
		"subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")

	// The company: a root, and an issuing CA it signed.
	mustRun(t, corp, nil, openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
		"-nodes", "-keyout", in("root.key"), "-out", in("root.crt"), "-days", "3650", "-subj", "/O=Corp/CN=Corp Root CA",
		"-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
	mustRun(t, corp, nil, openssl, "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
		"-nodes", "-keyout", in("issuing.key"), "-out", in("issuing.csr"), "-subj", "/O=Corp/CN=Corp Issuing CA")
	mustRun(t, corp, nil, openssl, "x509", "-req", "-in", in("issuing.csr"), "-CA", in("root.crt"), "-CAkey", in("root.key"),
		"-CAcreateserial", "-days", "3000", "-extfile", in("ca.ext"), "-out", in("issuing.crt"))

	// The issuing CA signs BastionXP CA's intermediate, under the root.
	mustRun(t, corp, nil, openssl, "x509", "-req", "-in", filepath.Join(c.dataDir, "intermediate.next.csr"),
		"-CA", in("issuing.crt"), "-CAkey", in("issuing.key"), "-CAcreateserial", "-days", "1800",
		"-extfile", in("ca.ext"), "-out", in("bastionxp-ca.crt"))
	c.admin("new-intermediate", "--import", in("bastionxp-ca.crt"),
		"--root-ca", in("root.crt"), "--issuing-ca", in("issuing.crt"))

	// The CA's root is now the company's.
	if !bytes.Equal(readCerts(t, c.root)[0].Raw, readCerts(t, in("root.crt"))[0].Raw) {
		t.Fatal("root.crt is not the company root")
	}
	c.start()
	c.trust()
	certFile, _ := c.issueTLS("corp.e2e.localhost")
	// Verified from the chain as delivered, nothing else: it must carry
	// the issuing CA too, or clients that know only the company root fail.
	if !opensslVerify(t, in("root.crt"), certFile, certFile) {
		t.Errorf("the chain delivered with the certificate does not reach the company root:\n%d certificates in %s", len(readCerts(t, certFile)), certFile)
	}
}

// A new SSH user CA key, in its two steps, with a real sshd: logins keep
// working throughout, as long as servers trust both keys during the
// change; afterwards only the new key's certificates are accepted where
// only the new key is trusted.
func TestNewSSHUserCA(t *testing.T) {
	sshKeygen, ssh := tool(t, "ssh-keygen"), tool(t, "ssh")
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	c := newCA(t, "")
	c.start()
	dir := t.TempDir()
	knownHosts := filepath.Join(dir, "known_hosts")
	c.client("trust", "--ca-url", c.url, "--fingerprint", c.fingerprint(), "--ssh", "--known-hosts", knownHosts)
	newKey := func(name string) string {
		key := filepath.Join(dir, name)
		mustRun(t, dir, nil, sshKeygen, "-q", "-t", "ed25519", "-N", "", "-f", key)
		return key
	}
	hostKey := newKey("host_key")
	c.client("ssh", "--token", c.token("ssh-host", "localhost"), "--key", hostKey+".pub")

	// What servers trust, as they would fetch it from the CA.
	trusted := filepath.Join(dir, "trusted_user_ca_keys")
	fetchTrusted := func() string {
		t.Helper()
		resp, err := c.httpsClient().Get(c.url + "/ssh_user_ca.pub")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}
	writeFile(t, trusted, fetchTrusted())
	port := startSSHD(t, dir, hostKey, trusted)
	login := func(key string) bool {
		t.Helper()
		return loggedIn(sshLogin(t, ssh, dir, port, me.Username, key, knownHosts))
	}

	oldUser := newKey("old_user")
	c.client("ssh", "--token", c.token("ssh-user", me.Username), "--key", oldUser+".pub")
	if !login(oldUser) {
		t.Fatal("login with the first key's certificate failed")
	}

	// Step 1: the next key. The CA lists both; servers add it.
	c.admin("new-ssh-ca", "user")
	if err := c.stop(); err != nil {
		t.Fatal(err)
	}
	c.start()
	both := fetchTrusted()
	if n := strings.Count(strings.TrimSpace(both), "\n") + 1; n != 2 {
		t.Fatalf("/ssh_user_ca.pub lists %d keys during the change, want 2:\n%s", n, both)
	}
	writeFile(t, trusted, both)
	if !login(oldUser) {
		t.Error("after step 1, the old certificate stopped working")
	}

	// Step 2: the next key signs. After a restart, new certificates come
	// from it; old ones still work while servers trust both.
	c.admin("new-ssh-ca", "user", "--activate")
	if err := c.stop(); err != nil {
		t.Fatal(err)
	}
	c.start()
	newUser := newKey("new_user")
	c.client("ssh", "--token", c.token("ssh-user", me.Username), "--key", newUser+".pub")
	if !login(newUser) {
		t.Error("login with a certificate from the new key failed")
	}
	if !login(oldUser) {
		t.Error("while servers trust both keys, the old certificate stopped working")
	}

	// Servers that trust only the new key now: old certificates are out.
	only := fetchTrusted()
	if n := strings.Count(strings.TrimSpace(only), "\n") + 1; n != 1 {
		t.Fatalf("/ssh_user_ca.pub lists %d keys after the change, want 1:\n%s", n, only)
	}
	writeFile(t, trusted, only)
	if !login(newUser) {
		t.Error("login with the new key's certificate failed where only it is trusted")
	}
	if login(oldUser) {
		t.Error("the old key's certificate still works where only the new key is trusted")
	}
}

// A backup taken while the server runs, restored into a fresh data
// directory: the server starts, knows what it knew then, revocation
// included, and issues again.
func TestBackupAndRestore(t *testing.T) {
	c := newCA(t, "")
	c.start()
	c.trust()
	var before []*x509.Certificate
	for _, name := range []string{"one.e2e.localhost", "two.e2e.localhost", "three.e2e.localhost"} {
		certFile, _ := c.issueTLS(name)
		before = append(before, readCerts(t, certFile)[0])
	}
	revoked := before[1].SerialNumber.Text(16)
	c.admin("revoke", revoked)

	backup := filepath.Join(t.TempDir(), "backup")
	c.admin("backup", "--out", backup)
	afterFile, _ := c.issueTLS("after.e2e.localhost") // not in the backup
	after := readCerts(t, afterFile)[0].SerialNumber.Text(16)

	// The backup is as private as the data directory.
	if info, err := os.Stat(backup); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Errorf("the backup directory is open to others: %v", info.Mode())
	}
	if info, err := os.Stat(filepath.Join(backup, "intermediate.key")); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Errorf("a key in the backup is open to others: %v %v", info, err)
	}

	// Restore, as the docs say: stop, put the copy in place, start.
	if err := c.stop(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(c.dataDir, c.dataDir+".broken"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, c.dataDir); err != nil {
		t.Fatal(err)
	}
	c.start()

	list := c.admin("list", "certificates").stdout
	for _, cert := range before {
		if !strings.Contains(list, cert.SerialNumber.Text(16)) {
			t.Errorf("certificate %x is missing after the restore", cert.SerialNumber)
		}
	}
	if strings.Contains(list, after) {
		t.Error("a certificate issued after the backup is in the restored database")
	}
	if !strings.Contains(c.admin("list", "certificates", "--revoked").stdout, revoked) {
		t.Error("the revocation is lost after the restore")
	}
	// And it works.
	certFile, _ := c.issueTLS("restored.e2e.localhost")
	c.verifyWithOpenSSL(certFile, "restored.e2e.localhost")
}
