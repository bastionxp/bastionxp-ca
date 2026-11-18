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
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
	"github.com/bastionxp/bastionxp-ca/internal/oidc/oidctest"
)

// testCA is a running BastionXP CA server with a fresh CA. The browser login is
// on, against a fake identity provider: ganesh is an admin, alice is a
// user who may log in to servers as "alice" and "deploy"; the groups
// linux-users and ca-admins have rules too.
type testCA struct {
	cfg  *config.Config
	url  string // https://127.0.0.1:<port>
	root string // path of root.crt
	idp  *oidctest.Fake
	acme *challengeTarget
}

// challengeTarget says where the CA's ACME challenge requests really go
// in a test: to the address of the command under test, in place of port
// 80 of the host that is being proved.
type challengeTarget struct {
	mu      sync.Mutex
	address string
	dialed  []string // the addresses the CA wanted to reach
}

func (c *challengeTarget) set(address string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.address = address
}

func (c *challengeTarget) dial(ctx context.Context, network, address string) (net.Conn, error) {
	c.mu.Lock()
	c.dialed = append(c.dialed, address)
	target := c.address
	c.mu.Unlock()
	if target == "" {
		return nil, errors.New("connection refused: nothing listens on port 80 in this test")
	}
	return (&net.Dialer{}).DialContext(ctx, network, target)
}

func (c *challengeTarget) wanted() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.dialed...)
}

// withPublicHTTP gives the CA a plain HTTP address for its public
// information, and makes it write that address into certificates.
func withPublicHTTP(cfg *config.Config) { cfg.Server.PublicAddress = "127.0.0.1:0" }

// withSCEP switches the SCEP server on. It is not on in every test,
// because making its RSA key takes a moment.
func withSCEP(cfg *config.Config) { cfg.SCEP.Enabled = true }

// startTestCA creates a CA and serves it on a free port until the test
// ends. changes can adjust the configuration first.
// testInit is what the tests give "bxp init": a root passphrase, and
// server keys that are not encrypted.
var testInit = initOptions{rootPassphrase: []byte("test root passphrase")}

func startTestCA(t *testing.T, changes ...func(*config.Config)) *testCA {
	t.Helper()
	idp := oidctest.NewFake("test-client-id", "test-client-secret")
	t.Cleanup(idp.Close)

	cfg := newTestConfig(t)
	cfg.OIDC = config.OIDC{
		Issuer: idp.Issuer(), ClientID: "test-client-id", ClientSecret: "test-client-secret",
		UsernameClaim: "preferred_username", GroupsClaim: "groups",
	}
	cfg.Access = []config.AccessRule{
		{Users: []string{"ganesh"}, Admin: true},
		{Users: []string{"alice"}, SSHPrincipals: []string{"alice", "deploy"}},
		{Groups: []string{"linux-users"}, SSHPrincipals: []string{"{short_username}"}},
		{Groups: []string{"ca-admins"}, Admin: true},
	}
	if err := runInit(io.Discard, cfg, testInit); err != nil {
		t.Fatal(err)
	}
	// ACME is on for example.com. The CA's challenge requests, which
	// would go to port 80 of the named host, are sent to whatever
	// address the test puts in acmeTarget.
	cfg.ACME = config.ACME{AllowedDomains: []string{"example.com"}}
	for _, change := range changes {
		change(cfg)
	}
	acmeTarget := &challengeTarget{}
	url := serveWith(t, cfg, serveHooks{ACMEDial: acmeTarget.dial})
	return &testCA{
		cfg:  cfg,
		url:  url,
		root: filepath.Join(cfg.DataDir, ca.RootCertFile),
		idp:  idp,
		acme: acmeTarget,
	}
}

// serveForTest serves an initialized CA on a free port until the test
// ends, and returns its URL.
func serveForTest(t *testing.T, cfg *config.Config) string {
	t.Helper()
	return serveWith(t, cfg, serveHooks{})
}

func serveWith(t *testing.T, cfg *config.Config, hooks serveHooks) string {
	t.Helper()
	listener, err := net.Listen("tcp", cfg.Server.Address)
	if err != nil {
		t.Fatal(err)
	}
	// The port is only known now. The provider sends browsers back to this
	// address, so it must be the real one.
	cfg.Server.URL = "https://" + listener.Addr().String()

	// A test that sets a public address gets the plain HTTP listener
	// too, on a free port, and finds its address in cfg.Server.PublicURL.
	var publicListener net.Listener
	if cfg.Server.PublicAddress != "" {
		publicListener, err = net.Listen("tcp", cfg.Server.PublicAddress)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Server.PublicURL = "http://" + publicListener.Addr().String()
	}

	ctx, stop := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- runServe(ctx, cfg, listener, publicListener, slog.New(slog.NewTextHandler(io.Discard, nil)), hooks)
	}()
	t.Cleanup(func() {
		stop()
		if err := <-served; err != nil {
			t.Errorf("server stopped with an error: %v", err)
		}
	})
	return "https://" + listener.Addr().String()
}

// connection returns the connection settings with a new token, as if the
// administrator had run "bxp token" and handed over the result.
func (c *testCA) connection(t *testing.T, template string, names ...string) connection {
	t.Helper()
	var out bytes.Buffer
	if err := runToken(&out, c.cfg, tokenOptions{template: template, names: names}); err != nil {
		t.Fatal(err)
	}
	return connection{url: c.url, root: c.root, token: strings.TrimSpace(out.String()), prompt: io.Discard}
}

// writeSSHKey writes a new SSH public key to dir/id_ed25519.pub.
func writeSSHKey(t *testing.T, dir string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id_ed25519.pub")
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// bxp tls writes a private key (mode 600) and a certificate for the names
// asked for, with the lifetime asked for, and says which files it wrote.
func TestTLS(t *testing.T) {
	testCA := startTestCA(t)
	conn := testCA.connection(t, "tls-server", "web.example.com", "10.0.0.5")
	outDir := t.TempDir()

	var out bytes.Buffer
	opts := tlsOptions{names: []string{"web.example.com", "10.0.0.5"}, outDir: outDir, validity: 24 * time.Hour}
	if err := runTLS(context.Background(), &out, conn, opts); err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(outDir, "web.example.com.key")
	certFile := filepath.Join(outDir, "web.example.com.crt")
	if !strings.Contains(out.String(), keyFile) || !strings.Contains(out.String(), certFile) {
		t.Errorf("output does not name the files written:\n%s", out.String())
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 600", perm)
	}

	// The two files must work together as a TLS server's key pair: this
	// fails if the certificate is not for the key.
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(pair.Certificate) != 2 {
		t.Fatalf("certificate file has %d certificates, want 2 (leaf and intermediate)", len(pair.Certificate))
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(pair.Certificate[1])
	if err != nil {
		t.Fatal(err)
	}

	// And a client that trusts only the root must accept them.
	authority, err := ca.Load(testCA.cfg.DataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority.RootCert())
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	for _, host := range []string{"web.example.com", "10.0.0.5"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: host}); err != nil {
			t.Errorf("certificate does not verify for %s: %v", host, err)
		}
	}
	if got := leaf.NotAfter.Sub(leaf.NotBefore).Round(time.Hour); got != 24*time.Hour {
		t.Errorf("validity = %s, want 24h", got)
	}
}

// bxp tls with a tls-client token writes a client-authentication certificate
// for the email address.
func TestTLSClientCertificate(t *testing.T) {
	testCA := startTestCA(t)
	conn := testCA.connection(t, "tls-client", "alice@example.com")
	outDir := t.TempDir()

	opts := tlsOptions{names: []string{"alice@example.com"}, outDir: outDir}
	if err := runTLS(context.Background(), io.Discard, conn, opts); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(outDir, "alice@example.com.crt"), filepath.Join(outDir, "alice@example.com.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != "alice@example.com" {
		t.Errorf("email addresses = %v, want [alice@example.com]", leaf.EmailAddresses)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("extended key usage = %v, want client auth only", leaf.ExtKeyUsage)
	}
}

// bxp tls does not replace existing files unless --force is given, and
// refuses before asking the CA, so the token still works.
func TestTLSDoesNotReplaceFilesWithoutForce(t *testing.T) {
	testCA := startTestCA(t)
	conn := testCA.connection(t, "tls-server", "web.example.com")
	outDir := t.TempDir()
	keyFile := filepath.Join(outDir, "web.example.com.key")
	if err := os.WriteFile(keyFile, []byte("old key"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := tlsOptions{names: []string{"web.example.com"}, outDir: outDir}

	err := runTLS(context.Background(), io.Discard, conn, opts)
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("error = %v, want one that mentions --force", err)
	}
	if content, _ := os.ReadFile(keyFile); string(content) != "old key" {
		t.Error("the existing key file was changed")
	}

	// The refusal came before the CA was asked, so the token still
	// works. With --force the files are replaced.
	opts.force = true
	if err := runTLS(context.Background(), io.Discard, conn, opts); err != nil {
		t.Fatalf("with --force: %v", err)
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(outDir, "web.example.com.crt"), keyFile); err != nil {
		t.Errorf("replaced files are not a key pair: %v", err)
	}
	// The old file was readable by everyone. The new key must not be.
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("replaced key file mode = %o, want 600", perm)
	}
}

// When the CA refuses a request, bxp tls reports the CA's reason and writes
// no files.
func TestTLSReportsRefusalAndWritesNothing(t *testing.T) {
	testCA := startTestCA(t)
	conn := testCA.connection(t, "tls-server", "web.example.com")
	outDir := t.TempDir()

	// Ask for a name the token does not allow.
	opts := tlsOptions{names: []string{"db.example.com"}, outDir: outDir}
	err := runTLS(context.Background(), io.Discard, conn, opts)
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("error = %v, want the CA's refusal", err)
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("%d files were written despite the refusal", len(entries))
	}
}

// bxp ssh writes a user certificate for the key in the file, with the
// token's principals, next to the key, and says which file and principals.
func TestSSHUser(t *testing.T) {
	testCA := startTestCA(t)
	conn := testCA.connection(t, "ssh-user", "alice", "deploy")
	keyFile := writeSSHKey(t, t.TempDir())

	var out bytes.Buffer
	if err := runSSH(context.Background(), &out, conn, sshOptions{keyFile: keyFile}); err != nil {
		t.Fatal(err)
	}

	certFile := strings.TrimSuffix(keyFile, ".pub") + "-cert.pub"
	if !strings.Contains(out.String(), certFile) || !strings.Contains(out.String(), "alice, deploy") {
		t.Errorf("output does not name the file and principals:\n%s", out.String())
	}
	certLine, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := parseSSHCert(string(certLine))
	if err != nil {
		t.Fatal(err)
	}

	// The certificate must be for the key in the file, and an SSH server
	// that trusts the user CA key must accept it.
	keyLine, _ := os.ReadFile(keyFile)
	wantKey, _, _, _, _ := ssh.ParseAuthorizedKey(keyLine)
	if !bytes.Equal(cert.Key.Marshal(), wantKey.Marshal()) {
		t.Error("the certificate is for a different key")
	}
	authority, err := ca.Load(testCA.cfg.DataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	checker := &ssh.CertChecker{
		IsUserAuthority: func(key ssh.PublicKey) bool {
			return bytes.Equal(key.Marshal(), authority.SSHUserCAPublicKey().Marshal())
		},
	}
	for _, principal := range []string{"alice", "deploy"} {
		if err := checker.CheckCert(principal, cert); err != nil {
			t.Errorf("certificate is not accepted for %s: %v", principal, err)
		}
	}
}

// bxp ssh with a host token gets a host certificate for the principal and
// lifetime asked for.
func TestSSHHostWithChosenPrincipalAndValidity(t *testing.T) {
	testCA := startTestCA(t)
	conn := testCA.connection(t, "ssh-host", "web1.example.com", "web1")
	keyFile := writeSSHKey(t, t.TempDir())

	opts := sshOptions{keyFile: keyFile, principals: []string{"web1.example.com"}, validity: 48 * time.Hour}
	if err := runSSH(context.Background(), io.Discard, conn, opts); err != nil {
		t.Fatal(err)
	}
	certLine, err := os.ReadFile(strings.TrimSuffix(keyFile, ".pub") + "-cert.pub")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := parseSSHCert(string(certLine))
	if err != nil {
		t.Fatal(err)
	}
	if cert.CertType != ssh.HostCert {
		t.Errorf("certificate type = %d, want a host certificate", cert.CertType)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "web1.example.com" {
		t.Errorf("principals = %v, want [web1.example.com]", cert.ValidPrincipals)
	}
	validity := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second
	if got := validity.Round(time.Hour); got != 48*time.Hour {
		t.Errorf("validity = %s, want 48h", got)
	}
}

// bxp ssh replaces an existing certificate file for the same key.
func TestSSHReplacesAnOldCertificate(t *testing.T) {
	testCA := startTestCA(t)
	keyFile := writeSSHKey(t, t.TempDir())
	certFile := strings.TrimSuffix(keyFile, ".pub") + "-cert.pub"
	if err := os.WriteFile(certFile, []byte("old certificate"), 0o644); err != nil {
		t.Fatal(err)
	}

	conn := testCA.connection(t, "ssh-user", "alice")
	if err := runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: keyFile}); err != nil {
		t.Fatal(err)
	}
	certLine, _ := os.ReadFile(certFile)
	if _, err := parseSSHCert(string(certLine)); err != nil {
		t.Errorf("the old certificate was not replaced: %v", err)
	}
}

// bxp ssh refuses before asking the CA when the key file is missing, is a
// private key's file name, does not exist, or is not an SSH public key.
func TestSSHRejectsBadKeyFiles(t *testing.T) {
	// No server is needed: all of these must fail before the CA is asked.
	conn := connection{url: "https://127.0.0.1:1", token: "tok"}
	dir := t.TempDir()
	notAKey := filepath.Join(dir, "notes.pub")
	if err := os.WriteFile(notAKey, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		keyFile string
		wantErr string
	}{
		{"no key file", "", "--key"},
		{"private key file name", filepath.Join(dir, "id_ed25519"), "ending in .pub"},
		{"missing file", filepath.Join(dir, "missing.pub"), "read SSH public key"},
		{"not a key", notAKey, "not an SSH public key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: tt.keyFile})
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// The client commands need a CA address, and an https:// one.
func TestClientNeedsAGoodURL(t *testing.T) {
	outDir := t.TempDir()
	opts := tlsOptions{names: []string{"web.example.com"}, outDir: outDir}

	tests := []struct {
		name    string
		conn    connection
		wantErr string
	}{
		{"no URL", connection{token: "tok"}, "--ca-url"},
		{"plain http", connection{url: "http://ca.example.com", token: "tok"}, "https://"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runTLS(context.Background(), io.Discard, tt.conn, opts)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// bxp tls without --name, and a token it cannot read the names from, asks
// for --name.
func TestTLSNeedsAName(t *testing.T) {
	conn := connection{url: "https://ca.example.com", token: "tok"}
	err := runTLS(context.Background(), io.Discard, conn, tlsOptions{outDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "--name") {
		t.Errorf("error = %v, want one that mentions --name", err)
	}
}

// The subject given to "bxp token" must show up in the key ID of the
// SSH certificate, all the way through the real server.
func TestTokenSubjectBecomesTheSSHKeyID(t *testing.T) {
	testCA := startTestCA(t)
	var out bytes.Buffer
	opts := tokenOptions{subject: "alice@example.com", template: "ssh-user", names: []string{"deploy"}}
	if err := runToken(&out, testCA.cfg, opts); err != nil {
		t.Fatal(err)
	}
	conn := connection{url: testCA.url, root: testCA.root, token: strings.TrimSpace(out.String())}
	keyFile := writeSSHKey(t, t.TempDir())

	if err := runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: keyFile}); err != nil {
		t.Fatal(err)
	}
	certLine, err := os.ReadFile(strings.TrimSuffix(keyFile, ".pub") + "-cert.pub")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := parseSSHCert(string(certLine))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cert.KeyId, "alice@example.com-") {
		t.Errorf("key ID = %q, want it to start with alice@example.com-", cert.KeyId)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "deploy" {
		t.Errorf("principals = %v, want [deploy]", cert.ValidPrincipals)
	}
}
