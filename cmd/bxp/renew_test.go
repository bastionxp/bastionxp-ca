// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// issueTLSFiles gets a TLS certificate with a token and returns the paths
// of its certificate and key files.
func (c *testCA) issueTLSFiles(t *testing.T, name string, validity time.Duration) (certFile, keyFile string) {
	t.Helper()
	outDir := t.TempDir()
	conn := c.connection(t, "tls-server", name)
	opts := tlsOptions{names: []string{name}, outDir: outDir, validity: validity}
	if err := runTLS(context.Background(), io.Discard, conn, opts); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(outDir, name+".crt"), filepath.Join(outDir, name+".key")
}

// renewConn is how "bxp renew" reaches the test CA: no token.
func (c *testCA) renewConn() connection {
	return connection{url: c.url, root: c.root, prompt: io.Discard}
}

func leafOf(t *testing.T, certFile, keyFile string) *x509.Certificate {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("the files are not a key pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// A fresh certificate is left alone: a daily timer does nothing for the
// first two thirds of its life.
func TestRenewNotYet(t *testing.T) {
	testCA := startTestCA(t)
	certFile, keyFile := testCA.issueTLSFiles(t, "web.example.com", 0)
	before, _ := os.ReadFile(certFile)

	var out bytes.Buffer
	if err := runRenew(context.Background(), &out, io.Discard, testCA.renewConn(), renewOptions{cert: certFile, key: keyFile}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Not yet") {
		t.Errorf("output:\n%s", out.String())
	}
	if after, _ := os.ReadFile(certFile); !bytes.Equal(before, after) {
		t.Error("the certificate was replaced although it was not time")
	}
}

// bxp renew of a TLS certificate: a new certificate and a new key that
// belong together, the same names and lifetime, the key file mode 600, no
// files left over, the --exec command run; the renewed certificate renews in
// turn.
func TestRenewTLS(t *testing.T) {
	testCA := startTestCA(t)
	certFile, keyFile := testCA.issueTLSFiles(t, "web.example.com", 48*time.Hour)
	old := leafOf(t, certFile, keyFile)
	marker := filepath.Join(t.TempDir(), "reloaded")

	var out bytes.Buffer
	opts := renewOptions{cert: certFile, key: keyFile, force: true}
	if runtime.GOOS != "windows" {
		opts.exec = "touch " + marker
	}
	if err := runRenew(context.Background(), &out, io.Discard, testCA.renewConn(), opts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Renewed:") {
		t.Errorf("output:\n%s", out.String())
	}

	renewed := leafOf(t, certFile, keyFile) // the files still belong together
	if renewed.SerialNumber.Cmp(old.SerialNumber) == 0 {
		t.Error("the certificate was not replaced")
	}
	if sameKey(renewed.PublicKey, old.PublicKey) {
		t.Error("the key was not replaced")
	}
	if strings.Join(renewed.DNSNames, ",") != strings.Join(old.DNSNames, ",") {
		t.Errorf("names = %v, want %v", renewed.DNSNames, old.DNSNames)
	}
	if got := renewed.NotAfter.Sub(renewed.NotBefore).Round(time.Hour); got != 48*time.Hour {
		t.Errorf("lifetime = %s, want 48h like the old one", got)
	}
	info, _ := os.Stat(keyFile)
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 600", perm)
	}
	// Nothing left over from writing the files.
	entries, _ := os.ReadDir(filepath.Dir(certFile))
	if len(entries) != 2 {
		t.Errorf("%d files in the directory, want the key and the certificate", len(entries))
	}
	if opts.exec != "" {
		if _, err := os.Stat(marker); err != nil {
			t.Error("the --exec command did not run")
		}
	}

	// The renewed certificate renews in turn.
	if err := runRenew(context.Background(), io.Discard, io.Discard, testCA.renewConn(), renewOptions{cert: certFile, key: keyFile, force: true}); err != nil {
		t.Errorf("second renewal: %v", err)
	}
}

// bxp renew of a revoked certificate fails, says so, and leaves the files as
// they were.
func TestRenewRefusedAfterRevocation(t *testing.T) {
	testCA := startTestCA(t)
	certFile, keyFile := testCA.issueTLSFiles(t, "web.example.com", 0)
	old := leafOf(t, certFile, keyFile)
	if err := runRevoke(context.Background(), io.Discard, testCA.cfg, old.SerialNumber.Text(16), "key-compromise", false); err != nil {
		t.Fatal(err)
	}
	err := runRenew(context.Background(), io.Discard, io.Discard, testCA.renewConn(), renewOptions{cert: certFile, key: keyFile, force: true})
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("error = %v, want one that says it was revoked", err)
	}
	if renewed := leafOf(t, certFile, keyFile); renewed.SerialNumber.Cmp(old.SerialNumber) != 0 {
		t.Error("the files were replaced despite the refusal")
	}
}

// bxp renew of an expired certificate fails and says a new token is needed.
func TestRenewRefusedWhenExpired(t *testing.T) {
	testCA := startTestCA(t)
	certFile, keyFile := testCA.issueTLSFiles(t, "web.example.com", time.Second)
	old := leafOf(t, certFile, keyFile)
	time.Sleep(time.Until(old.NotAfter) + 100*time.Millisecond)

	err := runRenew(context.Background(), io.Discard, io.Discard, testCA.renewConn(), renewOptions{cert: certFile, key: keyFile})
	if err == nil || !strings.Contains(err.Error(), "expired") || !strings.Contains(err.Error(), "token") {
		t.Errorf("error = %v, want one that says it expired and needs a token", err)
	}
}

// writeHostKey writes an SSH host key pair the way ssh-keygen does.
func writeHostKey(t *testing.T, dir string) (keyFile, pubFile string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile = filepath.Join(dir, "ssh_host_ed25519_key")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, _ := ssh.NewPublicKey(priv.Public())
	pubFile = keyFile + ".pub"
	if err := os.WriteFile(pubFile, ssh.MarshalAuthorizedKey(pub), 0o644); err != nil {
		t.Fatal(err)
	}
	return keyFile, pubFile
}

func readSSHCert(t *testing.T, path string) *ssh.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := parseSSHCert(string(data))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// bxp renew of an SSH host certificate: not before a third of its lifetime
// is left unless forced; the same host key and principals; refused once the
// certificate is revoked.
func TestRenewSSHHost(t *testing.T) {
	testCA := startTestCA(t)
	keyFile, pubFile := writeHostKey(t, t.TempDir())
	conn := testCA.connection(t, "ssh-host", "web1.example.com")
	if err := runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: pubFile}); err != nil {
		t.Fatal(err)
	}
	certFile := keyFile + "-cert.pub"
	old := readSSHCert(t, certFile)

	// Not yet: a fresh 30-day certificate.
	var out bytes.Buffer
	if err := runRenew(context.Background(), &out, io.Discard, testCA.renewConn(), renewOptions{cert: certFile, key: keyFile}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Not yet") {
		t.Errorf("output:\n%s", out.String())
	}

	if err := runRenew(context.Background(), io.Discard, io.Discard, testCA.renewConn(), renewOptions{cert: certFile, key: keyFile, force: true}); err != nil {
		t.Fatal(err)
	}
	renewed := readSSHCert(t, certFile)
	if renewed.Serial == old.Serial {
		t.Error("the certificate was not replaced")
	}
	if !bytes.Equal(renewed.Key.Marshal(), old.Key.Marshal()) || strings.Join(renewed.ValidPrincipals, ",") != "web1.example.com" {
		t.Errorf("renewed: principals %v; the host key must stay the same", renewed.ValidPrincipals)
	}

	// Revoked with --ssh: no more renewals.
	if err := runRevoke(context.Background(), io.Discard, testCA.cfg, strconv.FormatUint(renewed.Serial, 10), "key-compromise", true); err != nil {
		t.Fatal(err)
	}
	err := runRenew(context.Background(), io.Discard, io.Discard, testCA.renewConn(), renewOptions{cert: certFile, key: keyFile, force: true})
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("after revocation: error = %v, want a refusal", err)
	}
}

// bxp renew refuses missing files, a file that is not a certificate, an SSH
// key instead of a certificate, the wrong key, and an SSH user certificate.
func TestRenewRefusesBadInput(t *testing.T) {
	testCA := startTestCA(t)
	certFile, keyFile := testCA.issueTLSFiles(t, "web.example.com", 0)
	_, otherKey := testCA.issueTLSFiles(t, "other.example.com", 0)
	notACert := filepath.Join(t.TempDir(), "notes.txt")
	os.WriteFile(notACert, []byte("hello"), 0o644)
	_, pubFile := writeHostKey(t, t.TempDir())

	// A user certificate.
	userKey := writeSSHKey(t, t.TempDir())
	if err := runSSH(context.Background(), io.Discard, testCA.connection(t, "ssh-user", "alice"), sshOptions{keyFile: userKey}); err != nil {
		t.Fatal(err)
	}
	userCert := strings.TrimSuffix(userKey, ".pub") + "-cert.pub"

	tests := []struct {
		name    string
		opts    renewOptions
		wantErr string
	}{
		{"no files", renewOptions{}, "--cert"},
		{"not a certificate", renewOptions{cert: notACert, key: keyFile}, "neither"},
		{"an SSH key, not a certificate", renewOptions{cert: pubFile, key: keyFile}, "not a certificate"},
		{"the wrong key", renewOptions{cert: certFile, key: otherKey, force: true}, "is not the key"},
		{"an SSH user certificate", renewOptions{cert: userCert, key: userKey, force: true}, "only SSH host certificates"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runRenew(context.Background(), io.Discard, io.Discard, testCA.renewConn(), tt.opts)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// A certificate is due for renewal when a third of its lifetime or less is
// left.
func TestRenewDue(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(90 * 24 * time.Hour)
	tests := []struct {
		now  time.Time
		want bool
	}{
		{start, false},
		{start.Add(59 * 24 * time.Hour), false}, // more than a third left
		{start.Add(60 * 24 * time.Hour), true},  // exactly a third left
		{start.Add(89 * 24 * time.Hour), true},
	}
	for _, tt := range tests {
		if got := renewDue(start, end, tt.now); got != tt.want {
			t.Errorf("at %s: due = %v, want %v", tt.now.Sub(start), got, tt.want)
		}
	}
}

// The program that uses the certificate may read the key through its
// group. A renewal must not lock it out by tightening the permissions,
// nor open them up.
func TestRenewKeepsFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix file modes")
	}
	testCA := startTestCA(t)
	certFile, keyFile := testCA.issueTLSFiles(t, "web.example.com", 0)
	if err := os.Chmod(keyFile, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(certFile, 0o664); err != nil {
		t.Fatal(err)
	}
	keyBefore, _ := os.Stat(keyFile)

	if err := runRenew(context.Background(), io.Discard, io.Discard, testCA.renewConn(), renewOptions{cert: certFile, key: keyFile, force: true}); err != nil {
		t.Fatal(err)
	}
	keyAfter, _ := os.Stat(keyFile)
	certAfter, _ := os.Stat(certFile)
	if keyAfter.Mode().Perm() != 0o640 || certAfter.Mode().Perm() != 0o664 {
		t.Errorf("modes after renewal: key %o, cert %o; want 640 and 664 as before", keyAfter.Mode().Perm(), certAfter.Mode().Perm())
	}
	if os.SameFile(keyBefore, keyAfter) {
		t.Error("the key file was overwritten in place, not replaced")
	}
	// Owner and group are kept as well; without root, the test can only
	// see that they are still the test's own.
	if a, b := keyBefore.Sys(), keyAfter.Sys(); a != nil && b != nil && !sameOwner(keyBefore, keyAfter) {
		t.Error("the owner or group of the key file changed")
	}
}

// A program that has the old files open keeps reading the old content:
// the new files are new files, the old ones stay until it closes them.
func TestRenewDoesNotDisturbAnOpenFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("on Windows, replacing a file another program holds open can fail")
	}
	testCA := startTestCA(t)
	certFile, keyFile := testCA.issueTLSFiles(t, "web.example.com", 0)
	before, _ := os.ReadFile(certFile)

	open, err := os.Open(certFile) // a running server that holds the file
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()

	if err := runRenew(context.Background(), io.Discard, io.Discard, testCA.renewConn(), renewOptions{cert: certFile, key: keyFile, force: true}); err != nil {
		t.Fatal(err)
	}
	stillOld, err := io.ReadAll(open)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stillOld, before) {
		t.Error("the open file changed under the program that holds it")
	}
	if now, _ := os.ReadFile(certFile); bytes.Equal(now, before) {
		t.Error("a fresh read does not see the new certificate")
	}
}
