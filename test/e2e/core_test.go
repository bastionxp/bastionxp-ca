// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && !windows

package e2e

import (
	"crypto/x509"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The command line itself: version, unknown commands, and errors that
// come out before any question is asked.
func TestCommandLine(t *testing.T) {
	c := newCA(t, "")

	r := c.client("--version")
	if !strings.Contains(r.stdout, "bxp") {
		t.Errorf("--version printed %q", r.stdout)
	}

	r = c.bxp("no-such-command")
	if r.code == 0 || !strings.Contains(r.stderr, "unknown command") {
		t.Errorf("an unknown command:\n%s", r)
	}

	// A second init fails at once, without asking for a passphrase.
	r = c.bxp("init", "--config", c.config)
	if r.code == 0 || !strings.Contains(r.stderr, "already initialized") {
		t.Errorf("a second init:\n%s", r)
	}
	if strings.Contains(r.stderr, "Passphrase") {
		t.Errorf("a second init asked for a passphrase first:\n%s", r)
	}

	// "bxp fingerprint" says what openssl says about root.crt.
	r = mustRun(t, c.dir, nil, tool(t, "openssl"), "x509", "-in", c.root, "-noout", "-fingerprint", "-sha256")
	_, opensslFP, _ := strings.Cut(strings.TrimSpace(r.stdout), "=")
	normalize := func(s string) string { return strings.ToLower(strings.ReplaceAll(s, ":", "")) }
	if normalize(opensslFP) != normalize(c.fingerprint()) {
		t.Errorf("bxp fingerprint = %s, openssl says %s", c.fingerprint(), opensslFP)
	}

	// "bxp trust" refuses a wrong fingerprint.
	c.start()
	wrong := strings.Repeat("0", 64)
	r = c.bxp("trust", "--ca-url", c.url, "--fingerprint", wrong)
	if r.code == 0 {
		t.Errorf("trust with a wrong fingerprint succeeded:\n%s", r)
	}
}

// A TLS certificate with a token, checked by openssl, then revoked and
// seen as revoked by openssl through OCSP and the CRL.
func TestTLSAndRevocation(t *testing.T) {
	c := newCA(t, "")
	c.start()
	c.trust()

	const name = "web.e2e.localhost"
	out := t.TempDir()
	token := c.token("tls-server", name, "10.0.0.5")
	c.client("tls", "--token", token, "--name", name, "--name", "10.0.0.5", "--out-dir", out)
	certFile := filepath.Join(out, name+".crt")
	cert := c.verifyWithOpenSSL(certFile, name)
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "10.0.0.5" {
		t.Errorf("IP addresses = %v, want [10.0.0.5]", cert.IPAddresses)
	}
	if info, err := os.Stat(filepath.Join(out, name+".key")); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("the key file is readable by others: %v", info.Mode())
	}

	// A token works once.
	r := c.bxp("tls", "--token", token, "--name", name, "--out-dir", t.TempDir())
	if r.code == 0 {
		t.Errorf("a token was used twice:\n%s", r)
	}

	// The certificate says where to ask about revocation.
	if len(cert.OCSPServer) != 1 || !strings.HasPrefix(cert.OCSPServer[0], c.publicURL) {
		t.Fatalf("OCSP address = %v, want one at %s", cert.OCSPServer, c.publicURL)
	}
	if len(cert.CRLDistributionPoints) != 1 || !strings.HasPrefix(cert.CRLDistributionPoints[0], c.publicURL) {
		t.Fatalf("CRL address = %v, want one at %s", cert.CRLDistributionPoints, c.publicURL)
	}
	if got := ocspStatus(t, c, certFile, cert); got != "good" {
		t.Errorf("OCSP before revocation: %s, want good", got)
	}

	c.admin("revoke", cert.SerialNumber.Text(16), "--reason", "key-compromise")
	// "bxp revoke" writes to the database; the running server notices
	// within 5 seconds, logs it, and stops giving its cached answers.
	c.waitForLog("certificate revoked")

	if got := ocspStatus(t, c, certFile, cert); got != "revoked" {
		t.Errorf("OCSP after revocation: %s, want revoked", got)
	}
	crl := fetchCRL(t, c, cert.CRLDistributionPoints[0])
	found := false
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			found = true
		}
	}
	if !found {
		t.Errorf("the CRL does not list serial %x", cert.SerialNumber)
	}
	r = c.admin("list", "certificates", "--revoked")
	if !strings.Contains(r.stdout, cert.SerialNumber.Text(16)) {
		t.Errorf("list certificates --revoked does not show the certificate:\n%s", r)
	}
}

// ocspStatus asks the CA's OCSP responder with openssl, which also checks
// the response's signature against the root.
func ocspStatus(t *testing.T, c *testCA, certFile string, cert *x509.Certificate) string {
	t.Helper()
	leaf := filepath.Join(t.TempDir(), "leaf.pem")
	writeCert(t, leaf, cert)
	r := mustRun(t, c.dir, nil, tool(t, "openssl"), "ocsp",
		"-issuer", filepath.Join(c.dataDir, "intermediate.crt"),
		"-cert", leaf,
		"-url", cert.OCSPServer[0],
		"-CAfile", c.root)
	if !strings.Contains(r.stderr+r.stdout, "Response verify OK") {
		t.Fatalf("openssl could not verify the OCSP response:\n%s", r)
	}
	for _, status := range []string{"good", "revoked", "unknown"} {
		if strings.Contains(r.stdout, leaf+": "+status) {
			return status
		}
	}
	t.Fatalf("no status in the OCSP answer:\n%s", r)
	return ""
}

// fetchCRL downloads the CRL, has openssl check its signature, and parses
// it.
func fetchCRL(t *testing.T, c *testCA, url string) *x509.RevocationList {
	t.Helper()
	resp, err := c.httpsClient().Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	der, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	crlFile := filepath.Join(dir, "ca.crl")
	writeFile(t, crlFile, string(der))
	chain := filepath.Join(dir, "chain.pem")
	writeFile(t, chain, string(readFile(t, filepath.Join(c.dataDir, "intermediate.crt")))+string(readFile(t, c.root)))
	r := mustRun(t, c.dir, nil, tool(t, "openssl"), "crl", "-inform", "DER", "-in", crlFile, "-CAfile", chain, "-noout", "-verify")
	if !strings.Contains(r.stderr+r.stdout, "verify OK") {
		t.Fatalf("openssl could not verify the CRL:\n%s", r)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	return crl
}

// SSH user and host certificates, checked with ssh-keygen.
func TestSSH(t *testing.T) {
	sshKeygen := tool(t, "ssh-keygen")
	c := newCA(t, "")
	c.start()
	c.trust()
	dir := t.TempDir()

	for _, tc := range []struct {
		profile, name, kind, caKey string
	}{
		{"ssh-user", "deploy", "user certificate", "ssh_user_ca.pub"},
		{"ssh-host", "web1.e2e.localhost", "host certificate", "ssh_host_ca.pub"},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			c := c.in(t)
			key := filepath.Join(dir, tc.profile)
			mustRun(t, dir, nil, sshKeygen, "-q", "-t", "ed25519", "-N", "", "-f", key)
			c.client("ssh", "--token", c.token(tc.profile, tc.name), "--key", key+".pub")

			r := mustRun(t, dir, nil, sshKeygen, "-L", "-f", key+"-cert.pub")
			if !strings.Contains(r.stdout, tc.kind) {
				t.Errorf("not a %s:\n%s", tc.kind, r.stdout)
			}
			if !strings.Contains(r.stdout, "\n                "+tc.name+"\n") {
				t.Errorf("principal %s missing:\n%s", tc.name, r.stdout)
			}
			// Signed by the CA's key for this kind.
			fp := strings.Fields(mustRun(t, dir, nil, sshKeygen, "-l", "-f", filepath.Join(c.dataDir, tc.caKey)).stdout)[1]
			if !strings.Contains(r.stdout, "Signing CA: ") || !strings.Contains(r.stdout, fp) {
				t.Errorf("not signed by %s (%s):\n%s", tc.caKey, fp, r.stdout)
			}
		})
	}
}

// "bxp renew": nothing to do while the certificate is fresh, a new key and
// certificate with --force, the --exec command after it, and no renewal
// once revoked.
func TestRenew(t *testing.T) {
	c := newCA(t, "")
	c.start()
	c.trust()

	const name = "renew.e2e.localhost"
	out := t.TempDir()
	c.client("tls", "--token", c.token("tls-server", name), "--name", name, "--out-dir", out)
	certFile, keyFile := filepath.Join(out, name+".crt"), filepath.Join(out, name+".key")
	before := c.verifyWithOpenSSL(certFile, name)
	keyBefore := readFile(t, keyFile)

	r := c.client("renew", "--cert", certFile, "--key", keyFile)
	if !strings.Contains(r.stdout, "Not yet") {
		t.Errorf("a fresh certificate was renewed:\n%s", r)
	}

	marker := filepath.Join(out, "reloaded")
	c.client("renew", "--cert", certFile, "--key", keyFile, "--force", "--exec", "touch "+marker)
	after := c.verifyWithOpenSSL(certFile, name)
	if after.SerialNumber.Cmp(before.SerialNumber) == 0 {
		t.Error("the certificate did not change")
	}
	if string(readFile(t, keyFile)) == string(keyBefore) {
		t.Error("the key did not change: TLS renewal makes a new key")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("--exec did not run: %v", err)
	}

	c.admin("revoke", after.SerialNumber.Text(16))
	r = c.bxp("renew", "--cert", certFile, "--key", keyFile, "--force")
	if r.code == 0 {
		t.Errorf("a revoked certificate was renewed:\n%s", r)
	}
}

// The server as a process: reload on SIGHUP, a broken configuration
// ignored, a clean stop on SIGTERM, and everything still there after a
// restart.
func TestServerLifecycle(t *testing.T) {
	c := newCA(t, "")
	c.start()
	c.trust()

	const name = "life.e2e.localhost"
	c.client("tls", "--token", c.token("tls-server", name), "--name", name, "--out-dir", t.TempDir())

	// A broken configuration is not taken: the server goes on.
	good := readFile(t, c.config)
	writeFile(t, c.config, string(good)+"\nthis is not: [valid yaml\n")
	if err := c.server.Process.Signal(syscallHangup); err != nil {
		t.Fatal(err)
	}
	c.waitForLog("configuration not reloaded")
	if !c.running() {
		t.Fatal("the server stopped on a broken configuration")
	}

	// A good one is.
	writeFile(t, c.config, string(good))
	if err := c.server.Process.Signal(syscallHangup); err != nil {
		t.Fatal(err)
	}
	c.waitForLog("configuration reloaded")

	if err := c.stop(); err != nil {
		t.Fatalf("bxp serve did not exit cleanly on SIGTERM: %v", err)
	}

	// After a restart the CA still knows the certificate, and issues more.
	c.start()
	r := c.admin("list", "certificates")
	if !strings.Contains(r.stdout, name) {
		t.Errorf("the certificate is gone after a restart:\n%s", r)
	}
	c.client("tls", "--token", c.token("tls-server", "again."+name), "--name", "again."+name, "--out-dir", t.TempDir())
}
