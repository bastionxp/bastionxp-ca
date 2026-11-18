// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
)

// fingerprintOf returns the fingerprint of the test CA's root, as the
// administrator would hand it out.
func (c *testCA) fingerprintOf(t *testing.T) string {
	t.Helper()
	authority, err := ca.Load(c.cfg.DataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ca.CertFingerprint(authority.RootCert())
}

// useClientDir points the saved trust at a fresh directory for the test.
func useClientDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(envClientDir, dir)
	t.Setenv(envURL, "")
	t.Setenv(envRoot, "")
	return dir
}

// bxp trust with the right fingerprint saves the CA's address, without a
// trailing slash, and its root, and shows the fingerprint; running it again
// for the same CA is fine.
func TestTrust(t *testing.T) {
	testCA := startTestCA(t)
	dir := useClientDir(t)

	var out bytes.Buffer
	if err := runTrust(context.Background(), &out, trustOptions{url: testCA.url + "/", fingerprint: testCA.fingerprintOf(t)}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Trusted:") || !strings.Contains(out.String(), testCA.fingerprintOf(t)) {
		t.Errorf("output:\n%s", out.String())
	}

	saved, err := loadTrust()
	if err != nil || saved == nil {
		t.Fatalf("nothing saved: %v", err)
	}
	if saved.URL != testCA.url {
		t.Errorf("saved URL = %q, want %q (without the trailing slash)", saved.URL, testCA.url)
	}
	savedRoot, _ := os.ReadFile(filepath.Join(dir, trustRootFile))
	realRoot, _ := os.ReadFile(testCA.root)
	if !bytes.Equal(savedRoot, realRoot) {
		t.Error("the saved root is not the CA's root")
	}

	// Running it again for the same CA is fine.
	if err := runTrust(context.Background(), io.Discard, trustOptions{url: testCA.url, fingerprint: testCA.fingerprintOf(t)}); err != nil {
		t.Errorf("second run for the same CA: %v", err)
	}
}

// After "bxp trust", the other commands need neither --ca-url nor --root.
func TestOtherCommandsUseTheSavedTrust(t *testing.T) {
	testCA := startTestCA(t)
	useClientDir(t)
	if err := runTrust(context.Background(), io.Discard, trustOptions{url: testCA.url, fingerprint: testCA.fingerprintOf(t)}); err != nil {
		t.Fatal(err)
	}

	// The command as a person types it: only the token and the name.
	tok := testCA.connection(t, "tls-server", "web.example.com").token
	outDir := t.TempDir()
	cmd := newRootCommand()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"tls", "--token", tok, "--name", "web.example.com", "--out-dir", outDir})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "web.example.com.crt")); err != nil {
		t.Error(err)
	}
}

// The saved CA is used when no address is given or the saved one is; another
// address does not get the saved root; a root given is used.
func TestUseSavedTrust(t *testing.T) {
	useClientDir(t)
	// Nothing saved: nothing changes.
	conn := connection{}
	if err := conn.useSavedTrust(); err != nil || conn.url != "" || conn.root != "" {
		t.Errorf("without saved trust: %+v, %v", conn, err)
	}

	testCA := startTestCA(t)
	if err := runTrust(context.Background(), io.Discard, trustOptions{url: testCA.url, fingerprint: testCA.fingerprintOf(t)}); err != nil {
		t.Fatal(err)
	}
	saved, _ := loadTrust()

	tests := []struct {
		name     string
		given    connection
		wantURL  string
		wantRoot string
	}{
		{"nothing given", connection{}, saved.URL, saved.RootFile},
		{"the saved address given", connection{url: saved.URL + "/"}, saved.URL + "/", saved.RootFile},
		// The saved root is for the saved CA only.
		{"another address given", connection{url: "https://other.example.com"}, "https://other.example.com", ""},
		{"a root given", connection{root: "/my/root.crt"}, saved.URL, "/my/root.crt"},
	}
	for _, tt := range tests {
		conn := tt.given
		if err := conn.useSavedTrust(); err != nil {
			t.Fatal(err)
		}
		if conn.url != tt.wantURL || conn.root != tt.wantRoot {
			t.Errorf("%s: url %q root %q, want %q and %q", tt.name, conn.url, conn.root, tt.wantURL, tt.wantRoot)
		}
	}
}

// The whole point: a wrong fingerprint must stop everything.
func TestTrustRefusesAWrongFingerprint(t *testing.T) {
	testCA := startTestCA(t)
	other := startTestCA(t)
	dir := useClientDir(t)

	err := runTrust(context.Background(), io.Discard, trustOptions{url: testCA.url, fingerprint: other.fingerprintOf(t)})
	if err == nil || !strings.Contains(err.Error(), "does NOT have the fingerprint") {
		t.Fatalf("error = %v, want a refusal", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("%d files were saved despite the wrong fingerprint", len(entries))
	}
}

// A server that hands out a copy of the right root, which is public, but
// is not itself part of that CA: someone in the middle.
func TestTrustRefusesAServerThatOnlyCopiesTheRoot(t *testing.T) {
	testCA := startTestCA(t)
	dir := useClientDir(t)
	rootPEM, err := os.ReadFile(testCA.root)
	if err != nil {
		t.Fatal(err)
	}
	impostor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == ca.RootCertPath {
			w.Write(rootPEM)
			return
		}
		io.WriteString(w, `{"status":"ok"}`)
	}))
	defer impostor.Close()

	err = runTrust(context.Background(), io.Discard, trustOptions{url: impostor.URL, fingerprint: testCA.fingerprintOf(t)})
	if err == nil || !strings.Contains(err.Error(), "does not have a certificate from it") {
		t.Fatalf("error = %v, want a refusal", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("%d files were saved for the impostor", len(entries))
	}
}

// bxp trust refuses a missing, short or non-hex fingerprint, a missing
// address, plain HTTP, a server that is not a BastionXP CA, and an address
// where nothing listens.
func TestTrustRefusesBadInput(t *testing.T) {
	testCA := startTestCA(t)
	useClientDir(t)
	good := testCA.fingerprintOf(t)

	notOurCA := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html>hello</html>")
	}))
	defer notOurCA.Close()

	tests := []struct {
		name    string
		opts    trustOptions
		wantErr string
	}{
		{"no fingerprint", trustOptions{url: testCA.url}, "--fingerprint"},
		{"fingerprint too short", trustOptions{url: testCA.url, fingerprint: good[:40]}, "64 hex digits"},
		{"fingerprint not hex", trustOptions{url: testCA.url, fingerprint: strings.Repeat("z", 64)}, "64 hex digits"},
		{"no address", trustOptions{fingerprint: good}, "--ca-url"},
		{"plain http", trustOptions{url: "http://ca.example.com", fingerprint: good}, "invalid server URL"},
		{"not a BastionXP CA server", trustOptions{url: notOurCA.URL, fingerprint: good}, "root certificate"},
		{"nothing listening", trustOptions{url: "https://127.0.0.1:1", fingerprint: good}, "cannot reach"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runTrust(context.Background(), io.Discard, tt.opts)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// A fingerprint is accepted in upper case, with colons, as openssl prints it
// (the whole line too), with a SHA256: prefix, or with spaces around it.
func TestNormalizeFingerprint(t *testing.T) {
	plain := "9d4b7c0e11223344556677889900aabbccddeeff00112233445566778899aabb"
	colons := ""
	for i := 0; i < len(plain); i += 2 {
		if i > 0 {
			colons += ":"
		}
		colons += strings.ToUpper(plain[i : i+2])
	}
	for _, in := range []string{
		plain,
		strings.ToUpper(plain),
		colons,                         // as openssl prints it
		"SHA256 Fingerprint=" + colons, // openssl's whole line
		"SHA256:" + plain,
		"  " + plain + "\n",
	} {
		got, err := normalizeFingerprint(in)
		if err != nil || got != plain {
			t.Errorf("normalizeFingerprint(%q) = %q, %v", in, got, err)
		}
	}
}

// bxp trust for another CA needs --force to replace the saved one.
func TestTrustDoesNotReplaceAnotherCAWithoutForce(t *testing.T) {
	first := startTestCA(t)
	second := startTestCA(t)
	useClientDir(t)

	if err := runTrust(context.Background(), io.Discard, trustOptions{url: first.url, fingerprint: first.fingerprintOf(t)}); err != nil {
		t.Fatal(err)
	}
	err := runTrust(context.Background(), io.Discard, trustOptions{url: second.url, fingerprint: second.fingerprintOf(t)})
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("error = %v, want one that mentions --force", err)
	}
	if saved, _ := loadTrust(); saved.URL != first.url {
		t.Errorf("the saved CA changed to %s", saved.URL)
	}

	if err := runTrust(context.Background(), io.Discard, trustOptions{url: second.url, fingerprint: second.fingerprintOf(t), force: true}); err != nil {
		t.Fatal(err)
	}
	if saved, _ := loadTrust(); saved.URL != second.url {
		t.Errorf("with --force the saved CA is %s, want %s", saved.URL, second.url)
	}
}

// bxp trust --ssh adds the CA's SSH host key to known_hosts as a cert-
// authority line, once, beside the lines already there.
func TestTrustSSH(t *testing.T) {
	testCA := startTestCA(t)
	useClientDir(t)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := trustOptions{url: testCA.url, fingerprint: testCA.fingerprintOf(t), ssh: true, knownHosts: knownHosts}

	if err := runTrust(context.Background(), io.Discard, opts); err != nil {
		t.Fatal(err)
	}
	// Twice: the line must not be added twice.
	if err := runTrust(context.Background(), io.Discard, opts); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(knownHosts)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "github.com ") {
		t.Fatalf("known_hosts =\n%s\nwant the old line and one new one", data)
	}
	// The line is the CA's host key, in the form ssh reads.
	authority, _ := ca.Load(testCA.cfg.DataDir, nil)
	marker, hosts, key, _, _, err := ssh.ParseKnownHosts([]byte(lines[1]))
	if err != nil {
		t.Fatal(err)
	}
	if marker != "cert-authority" || len(hosts) != 1 || hosts[0] != "*" {
		t.Errorf("marker %q, hosts %v", marker, hosts)
	}
	if !bytes.Equal(key.Marshal(), authority.SSHHostCAPublicKey().Marshal()) {
		t.Error("the key in known_hosts is not the CA's SSH host key")
	}
}

// The trust command exists.
func TestTrustCommandIsThere(t *testing.T) {
	found := false
	for _, sub := range newRootCommand().Commands() {
		found = found || sub.Name() == "trust"
	}
	if !found {
		t.Error("there is no trust command")
	}
}
