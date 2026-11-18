// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/api"
)

// enrollForTest gets a certificate over SCEP and returns its files.
func enrollForTest(t *testing.T, testCA *testCA, name string) (certFile, keyFile string) {
	t.Helper()
	conn := testCA.connection(t, "tls-client", name)
	outDir := t.TempDir()
	if err := runSCEP(context.Background(), io.Discard, conn, scepOptions{names: []string{name}, outDir: outDir}); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(outDir, name+".crt"), filepath.Join(outDir, name+".key")
}

// bxp scep renew, with the certificate as the proof: not before it is due
// unless forced; a new certificate and RSA key of the same size, the same
// names and usages, with the intermediate in the file; a revoked certificate
// is refused and the files stay.
func TestSCEPRenew(t *testing.T) {
	testCA := startTestCA(t, withSCEP)
	certFile, keyFile := enrollForTest(t, testCA, "device1.example.com")
	before, _ := tls.LoadX509KeyPair(certFile, keyFile)
	conn := testCA.acmeConn() // no token: the certificate is the proof
	opts := renewOptions{cert: certFile, key: keyFile}

	// Not due yet: nothing happens.
	var out bytes.Buffer
	if err := runSCEPRenew(context.Background(), &out, io.Discard, conn, opts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Not yet") {
		t.Errorf("output:\n%s", out.String())
	}

	opts.force = true
	out.Reset()
	if err := runSCEPRenew(context.Background(), &out, io.Discard, conn, opts); err != nil {
		t.Fatal(err)
	}
	after, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Certificate) != 2 {
		t.Errorf("%d certificates in the file, want leaf and intermediate", len(after.Certificate))
	}
	oldLeaf, _ := x509.ParseCertificate(before.Certificate[0])
	newLeaf, _ := x509.ParseCertificate(after.Certificate[0])
	if oldLeaf.SerialNumber.Cmp(newLeaf.SerialNumber) == 0 || sameKey(oldLeaf.PublicKey, newLeaf.PublicKey) {
		t.Error("not a new certificate for a new key")
	}
	if !slices.Equal(newLeaf.DNSNames, oldLeaf.DNSNames) || !slices.Equal(newLeaf.ExtKeyUsage, oldLeaf.ExtKeyUsage) {
		t.Errorf("names %v, usages %v; want those of the old certificate", newLeaf.DNSNames, newLeaf.ExtKeyUsage)
	}
	if k, ok := after.PrivateKey.(*rsa.PrivateKey); !ok || k.N.BitLen() != before.PrivateKey.(*rsa.PrivateKey).N.BitLen() {
		t.Error("the new key is not an RSA key of the same size")
	}

	// A revoked certificate cannot renew.
	if err := runRevoke(context.Background(), io.Discard, testCA.cfg, serialHex(newLeaf), "key-compromise", false); err != nil {
		t.Fatal(err)
	}
	saved := mustRead(t, certFile)
	err = runSCEPRenew(context.Background(), io.Discard, io.Discard, conn, opts)
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("revoked certificate: error = %v, want a refusal", err)
	}
	if !bytes.Equal(mustRead(t, certFile), saved) {
		t.Error("files changed after a refusal")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// bxp scep getcert fetches an enrolled certificate again by serial number:
// the same file as at enrollment; an existing file needs --force; another
// device's key, an unknown serial number, and one that is not hex are
// refused.
func TestSCEPGetCert(t *testing.T) {
	testCA := startTestCA(t, withSCEP)
	certFile, keyFile := enrollForTest(t, testCA, "device1.example.com")
	leaf, err := readLeaf(certFile)
	if err != nil {
		t.Fatal(err)
	}
	conn := testCA.acmeConn()
	out := filepath.Join(t.TempDir(), "again.crt")

	var output bytes.Buffer
	if err := runSCEPGetCert(context.Background(), &output, conn, scepGetCertOptions{serial: serialHex(leaf), key: keyFile, out: out}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustRead(t, out), mustRead(t, certFile)) {
		t.Error("the fetched file differs from the one written at enrollment")
	}
	// The file exists now.
	err = runSCEPGetCert(context.Background(), io.Discard, conn, scepGetCertOptions{serial: serialHex(leaf), key: keyFile, out: out})
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("existing file: error = %v", err)
	}
	// Someone else's key: refused.
	_, otherKey := enrollForTest(t, testCA, "device2.example.com")
	err = runSCEPGetCert(context.Background(), io.Discard, conn, scepGetCertOptions{serial: serialHex(leaf), key: otherKey, out: out, force: true})
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("another key: error = %v, want a refusal", err)
	}
	// No such serial.
	err = runSCEPGetCert(context.Background(), io.Discard, conn, scepGetCertOptions{serial: "abc123", key: keyFile, out: out, force: true})
	if err == nil || !strings.Contains(err.Error(), "no such certificate") {
		t.Errorf("unknown serial: error = %v", err)
	}
	if err := runSCEPGetCert(context.Background(), io.Discard, conn, scepGetCertOptions{serial: "xyz", key: keyFile}); err == nil {
		t.Error("a serial that is not hex was accepted")
	}
}

// Each certificate is renewed the way it was obtained: bxp renew only
// for certificates from the API, SCEP renewal only for SCEP ones.
func TestRenewOnlyTheWayItWasObtained(t *testing.T) {
	testCA := startTestCA(t, withSCEP)
	ctx := context.Background()
	conn := testCA.acmeConn()

	scepCert, scepKey := enrollForTest(t, testCA, "device1.example.com")
	err := runRenew(ctx, io.Discard, io.Discard, conn, renewOptions{cert: scepCert, key: scepKey, force: true})
	if err == nil || !strings.Contains(err.Error(), "bxp scep renew") {
		t.Errorf("bxp renew of a SCEP certificate: error = %v", err)
	}

	acmeCert, acmeKey := issueForTest(t, testCA, "web.example.com")
	err = runRenew(ctx, io.Discard, io.Discard, conn, renewOptions{cert: acmeCert, key: acmeKey, force: true})
	if err == nil || !strings.Contains(err.Error(), "ACME client") {
		t.Errorf("bxp renew of an ACME certificate: error = %v", err)
	}

	// A certificate from the API, with an RSA key so that SCEP could
	// carry it: bxp renew works, SCEP renewal is refused.
	apiCert, apiKey := apiRSACertForTest(t, testCA, "laptop.example.com")
	err = runSCEPRenew(ctx, io.Discard, io.Discard, conn, renewOptions{cert: apiCert, key: apiKey, force: true})
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("SCEP renewal of an API certificate: error = %v", err)
	}
	if err := runRenew(ctx, io.Discard, io.Discard, conn, renewOptions{cert: apiCert, key: apiKey, force: true}); err != nil {
		t.Errorf("bxp renew of an API certificate: %v", err)
	}

	// The list says how each one was obtained.
	var list bytes.Buffer
	if err := runListCertificates(ctx, &list, testCA.cfg, false, "text"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"VIA", " scep ", " acme ", " api "} {
		if !strings.Contains(list.String(), want) {
			t.Errorf("list lacks %q:\n%s", want, list.String())
		}
	}
}

// apiRSACertForTest gets a certificate for an RSA key through the API
// with a token, as "bxp tls" does (which makes ECDSA keys).
func apiRSACertForTest(t *testing.T, testCA *testCA, name string) (certFile, keyFile string) {
	t.Helper()
	conn := testCA.connection(t, "tls-client", name)
	caClient, err := conn.newClient()
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{name}}, key)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := caClient.SignX509(context.Background(), conn.token,
		api.SignX509Request{CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, []byte(resp.Chain), 0o644); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
