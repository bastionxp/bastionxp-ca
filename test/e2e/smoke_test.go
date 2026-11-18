// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The basics on every system, Windows included: a CA, its server, and
// the client commands people use most. Checked with Go itself, not with
// openssl or ssh-keygen, which a Windows machine may not have. The other
// tests, with real clients and signals, run on Linux and macOS.
func TestSmoke(t *testing.T) {
	c := newCA(t, "")
	c.start()
	c.trust()

	// TLS: a certificate that chains to the root, for its name.
	const name = "smoke.e2e.localhost"
	out := t.TempDir()
	c.client("tls", "--token", c.token("tls-server", name), "--out-dir", out)
	certFile, keyFile := filepath.Join(out, name+".crt"), filepath.Join(out, name+".key")
	first := verifyWithGo(t, c, certFile, name)

	// SSH: a user certificate from the user CA, for the principal.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeFile(t, keyPath+".pub", string(ssh.MarshalAuthorizedKey(sshPub)))
	c.client("ssh", "--token", c.token("ssh-user", "deploy"), "--key", keyPath+".pub")
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(readFile(t, keyPath+"-cert.pub"))
	if err != nil {
		t.Fatal(err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("%s-cert.pub is not a certificate", keyPath)
	}
	userCA, _, _, _, err := ssh.ParseAuthorizedKey(readFile(t, filepath.Join(c.dataDir, "ssh_user_ca.pub")))
	if err != nil {
		t.Fatal(err)
	}
	if cert.CertType != ssh.UserCert || len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "deploy" ||
		!bytes.Equal(cert.SignatureKey.Marshal(), userCA.Marshal()) || !bytes.Equal(cert.Key.Marshal(), sshPub.Marshal()) {
		t.Errorf("SSH certificate: type %d, principals %v, signed by the user CA: %v",
			cert.CertType, cert.ValidPrincipals, bytes.Equal(cert.SignatureKey.Marshal(), userCA.Marshal()))
	}

	// Renewal: a new certificate for the same name.
	c.client("renew", "--cert", certFile, "--key", keyFile, "--force")
	renewed := verifyWithGo(t, c, certFile, name)
	if renewed.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Error("renewal did not change the certificate")
	}

	// The CA's list, and revocation.
	serial := renewed.SerialNumber.Text(16)
	if !strings.Contains(c.admin("list", "certificates").stdout, serial) {
		t.Error("the certificate is not in the list")
	}
	c.admin("revoke", serial)
	if !strings.Contains(c.admin("list", "certificates", "--revoked").stdout, serial) {
		t.Error("the revocation is not in the list")
	}

	// The setup checks out.
	if r := c.bxp("doctor", "--config", c.config); r.code != 0 {
		t.Errorf("bxp doctor:\n%s", r)
	}
}

// verifyWithGo checks with Go's crypto/x509 that the first certificate in
// certFile chains to the CA's root through the others in the file, for
// name, and returns it.
func verifyWithGo(t *testing.T, c *testCA, certFile, name string) *x509.Certificate {
	t.Helper()
	certs := readCerts(t, certFile)
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(readCerts(t, c.root)[0])
	for _, inter := range certs[1:] {
		intermediates.AddCert(inter)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{
		DNSName: name, Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("%s: %v", certFile, err)
	}
	return certs[0]
}
