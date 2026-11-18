// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
)

// The whole road with SCEP: a token as the challenge, a certificate back.
func TestSCEP(t *testing.T) {
	testCA := startTestCA(t, withSCEP)
	conn := testCA.connection(t, "tls-client", "device1.example.com")
	outDir := t.TempDir()

	var out bytes.Buffer
	opts := scepOptions{names: []string{"device1.example.com"}, outDir: outDir}
	if err := runSCEP(context.Background(), &out, conn, opts); err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(outDir, "device1.example.com.key")
	certFile := filepath.Join(outDir, "device1.example.com.crt")
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

	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, isRSA := pair.PrivateKey.(*rsa.PrivateKey); !isRSA {
		t.Errorf("the key is a %T, want RSA", pair.PrivateKey)
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
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
		DNSName: "device1.example.com", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Errorf("certificate does not verify: %v", err)
	}

	// The token is spent.
	opts.force = true
	err = runSCEP(context.Background(), io.Discard, conn, opts)
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("second use of the token: error = %v, want a refusal", err)
	}
}

// bxp scep enroll for a name not in the token is refused, and writes no
// files.
func TestSCEPRefusedForNamesNotInTheToken(t *testing.T) {
	testCA := startTestCA(t, withSCEP)
	conn := testCA.connection(t, "tls-client", "device1.example.com")
	outDir := t.TempDir()

	err := runSCEP(context.Background(), io.Discard, conn, scepOptions{names: []string{"device2.example.com"}, outDir: outDir})
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("error = %v, want a refusal", err)
	}
	entries, _ := os.ReadDir(outDir)
	if len(entries) != 0 {
		t.Errorf("%d files were written despite the refusal", len(entries))
	}
}

// Without --token, an admin logs in with the browser, as with the other
// client commands.
func TestSCEPWithBrowserLogin(t *testing.T) {
	testCA := startTestCA(t, withSCEP)
	admin, _ := testCA.browserAs(t, "ganesh")
	outDir := t.TempDir()

	opts := scepOptions{names: []string{"device1.example.com"}, template: "tls-client", outDir: outDir}
	if err := runSCEP(context.Background(), io.Discard, admin, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(outDir, "device1.example.com.crt"), filepath.Join(outDir, "device1.example.com.key")); err != nil {
		t.Error(err)
	}
}

// bxp scep enroll against a CA without SCEP says the server is not there,
// and the token still works for a normal request.
func TestSCEPWhenTheCAHasNoSCEP(t *testing.T) {
	testCA := startTestCA(t) // SCEP is off
	conn := testCA.connection(t, "tls-client", "device1.example.com")

	err := runSCEP(context.Background(), io.Discard, conn, scepOptions{names: []string{"device1.example.com"}, outDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("error = %v, want one that says the SCEP server is not there", err)
	}
	// The token was not sent anywhere, so it still works for a normal request.
	if err := runTLS(context.Background(), io.Discard, conn, tlsOptions{names: []string{"device1.example.com"}, outDir: t.TempDir()}); err != nil {
		t.Errorf("the token was spent although SCEP is off: %v", err)
	}
}

// A root file that cannot be read is an error, and the token is not sent.
// (That an RA of another CA is refused is tested in the scep package.)
func TestSCEPNeedsAReadableRootFile(t *testing.T) {
	testCA := startTestCA(t, withSCEP)
	conn := testCA.connection(t, "tls-client", "device1.example.com")
	goodRoot := conn.root

	conn.root = filepath.Join(t.TempDir(), "missing.crt")
	err := runSCEP(context.Background(), io.Discard, conn, scepOptions{names: []string{"device1.example.com"}, outDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected an error for a missing root file")
	}

	conn.root = goodRoot
	if err := runSCEP(context.Background(), io.Discard, conn, scepOptions{names: []string{"device1.example.com"}, outDir: t.TempDir()}); err != nil {
		t.Errorf("the token was spent by the failed attempt: %v", err)
	}
}

// bxp scep enroll fails before asking the CA with no names, an existing key
// file without --force, and no CA URL.
func TestSCEPChecksBeforeAskingTheCA(t *testing.T) {
	conn := connection{url: "https://127.0.0.1:1", token: "tok", prompt: io.Discard}
	outDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outDir, "device1.example.com.key"), []byte("old key"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runSCEP(context.Background(), io.Discard, conn, scepOptions{outDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "--name") {
		t.Errorf("no names: error = %v", err)
	}
	err = runSCEP(context.Background(), io.Discard, conn, scepOptions{names: []string{"device1.example.com"}, outDir: outDir})
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("file exists: error = %v", err)
	}
	err = runSCEP(context.Background(), io.Discard, connection{token: "tok"}, scepOptions{names: []string{"a"}, outDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "--ca-url") {
		t.Errorf("no URL: error = %v", err)
	}
}

// The static challenge password must be long enough: the server does not
// start with a short one.
func TestSCEPStaticPasswordLength(t *testing.T) {
	cfg := newTestConfig(t)
	if err := runInit(io.Discard, cfg, testInit); err != nil {
		t.Fatal(err)
	}
	cfg.SCEP = config.SCEP{Enabled: true, Static: config.SCEPStatic{ChallengeFile: writeSecret(t, "short"), X509: config.CertProfile{CertProfile: "tls-client"}}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	err = runServe(context.Background(), cfg, listener, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), serveHooks{})
	if err == nil || !strings.Contains(err.Error(), "at least 16 characters") {
		t.Errorf("error = %v, want a refusal of the short password", err)
	}
}
