// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
)

// freeAddress returns an address on this machine that nothing listens on.
func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

// acmeConn returns the connection settings for ACME: no token, no browser.
func (c *testCA) acmeConn() connection {
	return connection{url: c.url, root: c.root, prompt: io.Discard}
}

// The whole road with ACME: one command, no token and no login.
func TestACME(t *testing.T) {
	testCA := startTestCA(t)
	outDir := t.TempDir()
	// The command answers the challenge here. The test CA sends its
	// challenge requests to this address, in place of port 80.
	address := freeAddress(t)
	testCA.acme.set(address)

	var out bytes.Buffer
	opts := acmeOptions{names: []string{"web.example.com", "api.example.com"}, outDir: outDir, httpAddress: address}
	if err := runACME(context.Background(), &out, testCA.acmeConn(), opts); err != nil {
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

	// The two files work together, and a client that trusts only the
	// root accepts the certificate for both names.
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(pair.Certificate) != 2 {
		t.Fatalf("certificate file has %d certificates, want 2 (leaf and intermediate)", len(pair.Certificate))
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	intermediate, _ := x509.ParseCertificate(pair.Certificate[1])
	authority, err := ca.Load(testCA.cfg.DataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority.RootCert())
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	for _, host := range []string{"web.example.com", "api.example.com"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: host}); err != nil {
			t.Errorf("certificate does not verify for %s: %v", host, err)
		}
	}

	// The CA asked each host on port 80, as ACME says it must.
	wanted := strings.Join(testCA.acme.wanted(), " ")
	for _, want := range []string{"web.example.com:80", "api.example.com:80"} {
		if !strings.Contains(wanted, want) {
			t.Errorf("the CA did not ask %s (it asked: %s)", want, wanted)
		}
	}

	// The account key is kept, private, for the next request.
	accountKey := filepath.Join(outDir, "acme-account.key")
	info, err = os.Stat(accountKey)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("account key mode = %o, want 600", perm)
	}
	before, _ := os.ReadFile(accountKey)

	// A second request, for a renewal, uses the same account.
	opts.force = true
	if err := runACME(context.Background(), io.Discard, testCA.acmeConn(), opts); err != nil {
		t.Fatalf("second request: %v", err)
	}
	after, _ := os.ReadFile(accountKey)
	if !bytes.Equal(before, after) {
		t.Error("the account key was replaced by the second request")
	}
	renewed, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(renewed.Certificate[0], pair.Certificate[0]) {
		t.Error("the second request did not write a new certificate")
	}
}

// A machine that is not the host it names gets no certificate.
func TestACMEFailsWithoutControlOfTheHost(t *testing.T) {
	testCA := startTestCA(t)
	outDir := t.TempDir()

	// The command listens, but the CA's requests for the name do not
	// arrive here: the name points to some other machine.
	other := freeAddress(t)
	testCA.acme.set(other) // nothing listens there

	opts := acmeOptions{names: []string{"web.example.com"}, outDir: outDir, httpAddress: freeAddress(t)}
	err := runACME(context.Background(), io.Discard, testCA.acmeConn(), opts)
	if err == nil || !strings.Contains(err.Error(), "could not confirm") {
		t.Fatalf("error = %v, want one that says the CA could not confirm the host", err)
	}
	for _, name := range []string{"web.example.com.key", "web.example.com.crt"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err == nil {
			t.Errorf("%s was written although no certificate was issued", name)
		}
	}
}

// bxp acme issue for a name or wildcard outside the allowed domains reports
// the CA's refusal, and the CA contacts no host.
func TestACMERefusedForNamesOutsideTheAllowedDomains(t *testing.T) {
	testCA := startTestCA(t)
	address := freeAddress(t)
	testCA.acme.set(address)

	for _, name := range []string{"www.other.com", "*.other.com"} {
		opts := acmeOptions{names: []string{name}, outDir: t.TempDir(), httpAddress: address}
		err := runACME(context.Background(), io.Discard, testCA.acmeConn(), opts)
		if err == nil || !strings.Contains(err.Error(), "refused the order") {
			t.Errorf("%s: error = %v, want the CA's refusal", name, err)
		}
	}
	// The CA must not have contacted anybody for a refused name.
	if wanted := testCA.acme.wanted(); len(wanted) != 0 {
		t.Errorf("the CA made challenge requests for refused names: %v", wanted)
	}
}

// bxp acme issue fails against a CA without ACME.
func TestACMEWhenTheCAHasNoACME(t *testing.T) {
	cfg := newTestConfig(t) // no acme section
	if err := runInit(io.Discard, cfg, testInit); err != nil {
		t.Fatal(err)
	}
	conn := connection{url: serveForTest(t, cfg), root: filepath.Join(cfg.DataDir, ca.RootCertFile), prompt: io.Discard}

	opts := acmeOptions{names: []string{"web.example.com"}, outDir: t.TempDir(), httpAddress: freeAddress(t)}
	if err := runACME(context.Background(), io.Discard, conn, opts); err == nil {
		t.Fatal("expected an error from a CA without ACME, got nil")
	}
}

// bxp acme issue fails before asking the CA with no names, an existing key
// file without --force, no CA URL, a port that is taken, and a damaged
// account key.
func TestACMEChecksBeforeAskingTheCA(t *testing.T) {
	// No server is needed: all of these must fail before the CA is asked.
	conn := connection{url: "https://127.0.0.1:1", prompt: io.Discard}
	outDir := t.TempDir()
	existing := filepath.Join(outDir, "web.example.com.key")
	if err := os.WriteFile(existing, []byte("old key"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A port that is taken.
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()

	badKey := filepath.Join(t.TempDir(), "account.key")
	if err := os.WriteFile(badKey, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		conn    connection
		opts    acmeOptions
		wantErr string
	}{
		{"no names", conn, acmeOptions{outDir: t.TempDir()}, "--name"},
		{"file exists", conn, acmeOptions{names: []string{"web.example.com"}, outDir: outDir}, "--force"},
		{"no URL", connection{prompt: io.Discard}, acmeOptions{names: []string{"a.example.com"}, outDir: t.TempDir()}, "--ca-url"},
		{"port taken", conn, acmeOptions{names: []string{"a.example.com"}, outDir: t.TempDir(), httpAddress: taken.Addr().String()}, "cannot listen"},
		{"damaged account key", conn, acmeOptions{names: []string{"a.example.com"}, outDir: t.TempDir(), accountKey: badKey, httpAddress: "127.0.0.1:0"}, "account key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runACME(context.Background(), io.Discard, tt.conn, tt.opts)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
	if content, _ := os.ReadFile(existing); string(content) != "old key" {
		t.Error("the existing key file was changed")
	}
}

// tls-alpn-01: the CA connects to port 443, and the command answers with
// the challenge certificate.
func TestACMEWithTLSALPN01(t *testing.T) {
	testCA := startTestCA(t)
	outDir := t.TempDir()
	address := freeAddress(t)
	testCA.acme.set(address) // the CA's connection to port 443 lands here

	opts := acmeOptions{names: []string{"web.example.com"}, outDir: outDir, challenge: "tls-alpn-01", tlsAddress: address}
	if err := runACME(context.Background(), io.Discard, testCA.acmeConn(), opts); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(outDir, "web.example.com.crt"), filepath.Join(outDir, "web.example.com.key")); err != nil {
		t.Fatal(err)
	}
	for _, wanted := range testCA.acme.wanted() {
		if !strings.HasSuffix(wanted, ":443") {
			t.Errorf("the CA connected to %s, want port 443", wanted)
		}
	}
}

// A wildcard needs dns-01, which this command cannot answer: it says so
// instead of failing later.
func TestACMEWildcardNeedsDNS(t *testing.T) {
	testCA := startTestCA(t)
	address := freeAddress(t)
	testCA.acme.set(address)
	opts := acmeOptions{names: []string{"*.example.com"}, outDir: t.TempDir(), httpAddress: address}
	err := runACME(context.Background(), io.Discard, testCA.acmeConn(), opts)
	if err == nil || !strings.Contains(err.Error(), "dns-01") {
		t.Errorf("error = %v, want a hint about dns-01", err)
	}
	if err := runACME(context.Background(), io.Discard, testCA.acmeConn(),
		acmeOptions{names: []string{"web.example.com"}, challenge: "dns-01", outDir: t.TempDir()}); err == nil {
		t.Error("--challenge dns-01 was accepted")
	}
}

// An IP address, with each challenge that can prove one.
func TestACMEForAnIPAddress(t *testing.T) {
	for _, challenge := range []string{"http-01", "tls-alpn-01"} {
		t.Run(challenge, func(t *testing.T) {
			testCA := startTestCA(t, func(cfg *config.Config) { cfg.ACME.AllowedIPRanges = []string{"10.0.0.0/8"} })
			address := freeAddress(t)
			testCA.acme.set(address)
			outDir := t.TempDir()
			opts := acmeOptions{names: []string{"10.0.0.5"}, outDir: outDir, challenge: challenge, httpAddress: address, tlsAddress: address}
			if err := runACME(context.Background(), io.Discard, testCA.acmeConn(), opts); err != nil {
				t.Fatal(err)
			}
			pair, err := tls.LoadX509KeyPair(filepath.Join(outDir, "10.0.0.5.crt"), filepath.Join(outDir, "10.0.0.5.key"))
			if err != nil {
				t.Fatal(err)
			}
			leaf, _ := x509.ParseCertificate(pair.Certificate[0])
			if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "10.0.0.5" || len(leaf.DNSNames) != 0 {
				t.Errorf("IPs %v, DNS names %v", leaf.IPAddresses, leaf.DNSNames)
			}
		})
	}
	// Outside the ranges.
	testCA := startTestCA(t, func(cfg *config.Config) { cfg.ACME.AllowedIPRanges = []string{"10.0.0.0/8"} })
	err := runACME(context.Background(), io.Discard, testCA.acmeConn(), acmeOptions{names: []string{"192.168.1.1"}, outDir: t.TempDir(), httpAddress: freeAddress(t)})
	if err == nil || !strings.Contains(err.Error(), "refused the order") {
		t.Errorf("error = %v, want the CA's refusal", err)
	}
}

// The administrator revokes an ACME certificate like any other.
func TestRevokeACMECertificate(t *testing.T) {
	testCA := startTestCA(t)
	address := freeAddress(t)
	testCA.acme.set(address)
	outDir := t.TempDir()
	if err := runACME(context.Background(), io.Discard, testCA.acmeConn(), acmeOptions{names: []string{"web.example.com"}, outDir: outDir, httpAddress: address}); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(outDir, "web.example.com.crt"), filepath.Join(outDir, "web.example.com.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	var out bytes.Buffer
	if err := runRevoke(context.Background(), &out, testCA.cfg, leaf.SerialNumber.Text(16), "key-compromise", false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "web.example.com") {
		t.Errorf("output:\n%s", out.String())
	}
}
