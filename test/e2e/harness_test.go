// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

// Package e2e runs the real bxp binary the way people do: it builds it,
// creates a CA with "bxp init", starts "bxp serve" as its own process, and
// gets certificates with bxp and with other programs (openssl, ssh-keygen,
// certbot, lego, acme.sh, scepclient). Run it with "make test-e2e"; see
// README.md.
package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// bxpBin is the bxp binary built for this run.
var bxpBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "bxp-e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	bxpBin = filepath.Join(dir, "bxp")
	if runtime.GOOS == "windows" {
		bxpBin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bxpBin, "github.com/bastionxp/bastionxp-ca/cmd/bxp")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build bxp:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// tool finds a program the tests need: in $BXP_E2E_TOOLS/bin (where "make
// e2e-tools" puts the ACME and SCEP clients), or else on the PATH. A
// missing tool skips the test, unless BXP_E2E_REQUIRE_ALL is set (as in
// CI), where it fails it: there, a skipped test would hide a gap.
func tool(t *testing.T, name string) string {
	t.Helper()
	if dir := os.Getenv("BXP_E2E_TOOLS"); dir != "" {
		path := filepath.Join(dir, "bin", name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	missing(t, "%s is not installed: run \"make e2e-tools\", or install it", name)
	return ""
}

// missing skips the test, or fails it with BXP_E2E_REQUIRE_ALL set.
func missing(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("BXP_E2E_REQUIRE_ALL") != "" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// result is what a program printed and how it ended.
type result struct {
	stdout, stderr string
	code           int
}

func (r result) String() string {
	return fmt.Sprintf("exit code %d\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
}

// run runs a program in dir with env added to this process's environment,
// and fails the test only if it could not be started.
func run(t *testing.T, dir string, env []string, name string, args ...string) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	r := result{stdout: stdout.String(), stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		r.code = exitErr.ExitCode()
	case err != nil:
		t.Fatalf("run %s: %v", name, err)
	}
	return r
}

// mustRun is run for a program that must succeed.
func mustRun(t *testing.T, dir string, env []string, name string, args ...string) result {
	t.Helper()
	r := run(t, dir, env, name, args...)
	if r.code != 0 {
		t.Fatalf("%s %s failed:\n%s", filepath.Base(name), strings.Join(args, " "), r)
	}
	return r
}

// freePort returns a TCP port on 127.0.0.1 that nothing listens on.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// testCA is a CA made with "bxp init" in its own directory, and its
// server once started.
type testCA struct {
	t         *testing.T
	dir       string // the working directory of every command
	config    string // bastionxp-ca.yaml
	dataDir   string
	url       string // https://127.0.0.1:<port>
	publicURL string // http://127.0.0.1:<port>
	root      string // the root certificate, root.crt
	env       []string

	// serveArgs and serveEnv are added to "bxp serve" and its environment.
	serveArgs []string
	serveEnv  []string

	server *exec.Cmd
	done   chan error // the server's exit, once it ended
	logs   *syncBuffer
}

// caOptions change how newCAWith makes a CA.
type caOptions struct {
	// caYAML is added to the "ca:" section, indented two spaces.
	caYAML string
	// extraYAML is added at the end of the configuration.
	extraYAML string
	// initEnv is added to the environment of "bxp init".
	initEnv []string
	// externalRoot makes a CA under another root: "bxp init
	// --external-root". Its intermediate is then still to be imported.
	externalRoot bool
}

const rootPassphrase = "e2e root key passphrase"

// newCA creates a CA in a new directory with "bxp init". extraYAML is
// added to the configuration, for ACME or SCEP.
func newCA(t *testing.T, extraYAML string) *testCA {
	t.Helper()
	return newCAWith(t, caOptions{extraYAML: extraYAML})
}

// newCAWith is newCA with more choices.
func newCAWith(t *testing.T, opts caOptions) *testCA {
	t.Helper()
	dir := t.TempDir()
	c := &testCA{
		t:       t,
		dir:     dir,
		config:  filepath.Join(dir, "bastionxp-ca.yaml"),
		dataDir: filepath.Join(dir, "data"),
		logs:    &syncBuffer{},
	}
	port, publicPort := freePort(t), freePort(t)
	c.url = fmt.Sprintf("https://127.0.0.1:%d", port)
	c.publicURL = fmt.Sprintf("http://127.0.0.1:%d", publicPort)
	c.root = filepath.Join(c.dataDir, "root.crt")
	// Clients keep what "bxp trust" saves, and ssh-keygen its files, in
	// the test's own directory, never in the user's home.
	c.env = []string{
		"HOME=" + filepath.Join(dir, "home"),
		"BXP_CLIENT_DIR=" + filepath.Join(dir, "client"),
	}
	writeFile(t, c.config, fmt.Sprintf(`data_dir: %s
ca:
  name: E2E
  organization: E2E Org
%s
server:
  address: 127.0.0.1:%d
  names: [localhost, 127.0.0.1]
  public_address: 127.0.0.1:%d
  public_url: %s
%s`, c.dataDir, indent(opts.caYAML, "  "), port, publicPort, c.publicURL, opts.extraYAML))

	passphraseFile := filepath.Join(dir, "root-passphrase")
	writeFile(t, passphraseFile, rootPassphrase+"\n")
	initArgs := []string{"init", "--root-passphrase-file", passphraseFile, "--config", c.config}
	if opts.externalRoot {
		initArgs = []string{"init", "--external-root", "--config", c.config}
	}
	mustRun(t, dir, append(append([]string{}, c.env...), opts.initEnv...), bxpBin, initArgs...)
	return c
}

// indent puts prefix before every line of text.
func indent(text, prefix string) string {
	if text == "" {
		return ""
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n")
}

// bxp runs bxp and returns what happened, whatever the exit code.
func (c *testCA) bxp(args ...string) result {
	c.t.Helper()
	return run(c.t, c.dir, c.env, bxpBin, args...)
}

// client runs a bxp command that must succeed.
func (c *testCA) client(args ...string) result {
	c.t.Helper()
	return mustRun(c.t, c.dir, c.env, bxpBin, args...)
}

// admin runs a bxp command on the CA machine, with the configuration, that
// must succeed.
func (c *testCA) admin(args ...string) result {
	c.t.Helper()
	return c.client(append(args, "--config", c.config)...)
}

// token creates a one-time token on the CA machine.
func (c *testCA) token(profile string, names ...string) string {
	c.t.Helper()
	args := []string{"token", "--profile", profile}
	for _, n := range names {
		args = append(args, "--name", n)
	}
	return strings.TrimSpace(c.admin(args...).stdout)
}

// start starts "bxp serve" and waits until it answers.
func (c *testCA) start() {
	c.t.Helper()
	if c.server == nil {
		c.t.Cleanup(func() {
			if c.t.Failed() {
				c.t.Logf("server log:\n%s", c.logs)
			}
		})
	}
	c.server = exec.Command(bxpBin, append([]string{"serve", "--config", c.config}, c.serveArgs...)...)
	c.server.Dir = c.dir
	c.server.Env = append(append(os.Environ(), c.env...), c.serveEnv...)
	c.server.Stdout, c.server.Stderr = c.logs, c.logs
	if err := c.server.Start(); err != nil {
		c.t.Fatal(err)
	}
	done := make(chan error, 1)
	c.done = done
	go func() { done <- c.server.Wait() }()
	// Each start cleans up its own process: a test may restart the server.
	server := c.server
	c.t.Cleanup(func() {
		select {
		case err := <-done:
			done <- err
		default:
			server.Process.Kill()
			done <- <-done
		}
	})

	client := c.httpsClient()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-c.done:
			c.done <- err
			c.t.Fatalf("bxp serve ended at startup: %v\n%s", err, c.logs)
		default:
		}
		resp, err := client.Get(c.url + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	c.t.Fatalf("bxp serve did not answer within 20s\n%s", c.logs)
}

// running reports whether the server process is still running.
func (c *testCA) running() bool {
	if c.done == nil {
		return false
	}
	select {
	case err := <-c.done:
		c.done <- err
		return false
	default:
		return true
	}
}

// stop sends SIGTERM to the server and returns how it ended.
func (c *testCA) stop() error {
	c.t.Helper()
	if err := c.server.Process.Signal(stopSignal); err != nil {
		c.t.Fatal(err)
	}
	select {
	case err := <-c.done:
		c.done <- err
		return err
	case <-time.After(20 * time.Second):
		c.t.Fatalf("bxp serve did not stop within 20s after SIGTERM\n%s", c.logs)
		return nil
	}
}

// waitForLog waits until the server's log contains text.
func (c *testCA) waitForLog(text string) {
	c.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(c.logs.String(), text) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	c.t.Fatalf("the server log never said %q:\n%s", text, c.logs)
}

// httpsClient trusts the CA's root, as a client that ran "bxp trust" does.
func (c *testCA) httpsClient() *http.Client {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(readFile(c.t, c.root))
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
}

// fingerprint is the root's fingerprint, as "bxp fingerprint" prints it.
func (c *testCA) fingerprint() string {
	c.t.Helper()
	return strings.TrimSpace(c.admin("fingerprint").stdout)
}

// trust runs "bxp trust", as the first step on every client.
func (c *testCA) trust() {
	c.t.Helper()
	c.client("trust", "--ca-url", c.url, "--fingerprint", c.fingerprint())
}

// syncBuffer is a bytes.Buffer that a running process and the test can
// use at the same time.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// readCerts reads the PEM certificates in a file, leaf first.
func readCerts(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	rest := readFile(t, path)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		t.Fatalf("%s holds no certificate", path)
	}
	return certs
}

// writeCert writes one certificate as PEM, for openssl.
func writeCert(t *testing.T, path string, cert *x509.Certificate) {
	t.Helper()
	writeFile(t, path, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
}

// in returns the CA for use in subtest t, so that failures are reported
// there and not on the parent test.
func (c *testCA) in(t *testing.T) *testCA {
	sub := *c
	sub.t = t
	return &sub
}

// verifyWithOpenSSL checks with openssl that the first certificate in
// chainFile leads up to the CA's root through the CA's intermediate, for
// a TLS server, and that it holds the DNS name.
func (c *testCA) verifyWithOpenSSL(chainFile, dnsName string) *x509.Certificate {
	c.t.Helper()
	return c.verifyWithOpenSSLFor("sslserver", chainFile, dnsName)
}

// verifyWithOpenSSLFor is verifyWithOpenSSL for an openssl purpose:
// sslserver or sslclient.
func (c *testCA) verifyWithOpenSSLFor(purpose, chainFile, dnsName string) *x509.Certificate {
	c.t.Helper()
	openssl := tool(c.t, "openssl")
	certs := readCerts(c.t, chainFile)
	leaf := filepath.Join(c.t.TempDir(), "leaf.pem")
	writeCert(c.t, leaf, certs[0])
	r := mustRun(c.t, c.dir, nil, openssl, "verify",
		"-CAfile", c.root,
		"-untrusted", filepath.Join(c.dataDir, "intermediate.crt"),
		"-purpose", purpose,
		leaf)
	if !strings.Contains(r.stdout, ": OK") {
		c.t.Fatalf("openssl verify:\n%s", r)
	}
	if dnsName != "" {
		if err := certs[0].VerifyHostname(dnsName); err != nil {
			c.t.Fatalf("%s: %v", chainFile, err)
		}
	}
	return certs[0]
}

// serialHex is a certificate's serial number as openssl prints it.
func serialHex(cert *x509.Certificate) string {
	return strings.ToUpper(cert.SerialNumber.Text(16))
}

// assertRevoked checks that the CA lists the first certificate in
// certFile as revoked.
func (c *testCA) assertRevoked(certFile string) {
	c.t.Helper()
	serial := readCerts(c.t, certFile)[0].SerialNumber.Text(16)
	revoked := c.admin("list", "certificates", "--revoked").stdout
	if !strings.Contains(revoked, serial) {
		c.t.Errorf("%s (serial %s) is not revoked:\n%s", certFile, serial, revoked)
	}
}

// serveFails runs "bxp serve" with env added, expecting it to stop by
// itself at startup, and returns how it ended.
func (c *testCA) serveFails(env ...string) result {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bxpBin, "serve", "--config", c.config)
	cmd.Dir = c.dir
	cmd.Env = append(append(os.Environ(), c.env...), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		c.t.Fatalf("bxp serve did not stop by itself:\n%s%s", stdout.String(), stderr.String())
	}
	r := result{stdout: stdout.String(), stderr: stderr.String()}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		r.code = exitErr.ExitCode()
	}
	return r
}

// sleepShort waits a moment, between polls.
func sleepShort() { time.Sleep(50 * time.Millisecond) }

// osChmod is os.Chmod, for files a test writes and then runs.
func osChmod(path string, mode os.FileMode) error { return os.Chmod(path, mode) }

// fileExists reports whether path exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
