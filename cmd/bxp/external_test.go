// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/ca/catest"
)

func writePEM(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "certs.pem")
	if err := os.WriteFile(path, ca.EncodeCertPEM(certs...), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// The whole road under a company root: init makes a CSR, the company's CA
// signs it, the import puts it in place, and certificates from BastionXP CA are
// trusted by machines that only know the company root.
func TestExternalRoot(t *testing.T) {
	corp := catest.NewCorp(t)
	cfg := newTestConfig(t)
	var out bytes.Buffer
	if err := runInitExternal(&out, cfg, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "certreq") || !strings.Contains(out.String(), "--import") {
		t.Errorf("init output does not say what to do next:\n%s", out.String())
	}

	// Until the import: a clear message from doctor and from serve.
	if r, report := doctor(t, cfg); r.fails != 1 {
		t.Errorf("doctor:\n%s", report)
	} else {
		wantLine(t, report, "FAIL", "waits for its intermediate certificate")
	}
	if _, err := loadServerKeys(cfg, io.Discard); !errors.Is(err, ca.ErrWaitingForIntermediate) {
		t.Errorf("serve before the import: %v", err)
	}

	csr, err := os.ReadFile(filepath.Join(cfg.DataDir, ca.NextIntermediateCSRFile))
	if err != nil {
		t.Fatal(err)
	}
	signed := corp.SignSubCA(t, csr, catest.SubCAOptions{})
	opts := replaceOptions{importCert: writePEM(t, signed), issuingCAs: []string{writePEM(t, catest.NewCorp(t).Root), writePEM(t, corp.Issuing)}, rootCA: writePEM(t, corp.Root)}
	if err := runImportIntermediate(context.Background(), io.Discard, io.Discard, cfg, opts); err != nil {
		t.Fatal(err)
	}

	// Served, and a machine that trusts only the company root accepts the
	// certificates: the chain goes along.
	url := serveForTest(t, cfg)
	testCA := &testCA{cfg: cfg, url: url, root: filepath.Join(cfg.DataDir, ca.RootCertFile)}
	outDir := t.TempDir()
	conn := testCA.connection(t, "tls-server", "web.example.com")
	if err := runTLS(context.Background(), io.Discard, conn, tlsOptions{names: []string{"web.example.com"}, outDir: outDir}); err != nil {
		t.Fatal(err)
	}
	chainPEM, err := os.ReadFile(filepath.Join(outDir, "web.example.com.crt"))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ca.ParseCerts(chainPEM)
	if err != nil || len(chain) != 3 {
		t.Fatalf("the certificate file has %d certificates, want leaf, BastionXP CA's intermediate and the issuing CA", len(chain))
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(corp.Root)
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "web.example.com"}); err != nil {
		t.Errorf("not trusted under the company root: %v", err)
	}
	if r, report := doctor(t, cfg); r.fails != 0 {
		t.Errorf("doctor after the import:\n%s", report)
	}
}
