// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/ca/catest"
)

var initOpts = ca.InitOptions{Name: "Zero", Organization: "Corp", KeyType: ca.KeyTypeECDSA}

func externalCA(t *testing.T) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	csr, err := ca.InitExternal(dir, initOpts)
	if err != nil {
		t.Fatal(err)
	}
	return dir, csr
}

// A CA under a company root: waits for its intermediate, imports the signed
// chain in any order with extra certificates, has the company's root; its
// certificates are accepted by a machine that trusts only the company root,
// and its CRL is signed by its intermediate.
func TestUnderAnotherRoot(t *testing.T) {
	corp := catest.NewCorp(t)
	dir, csr := externalCA(t)
	if _, err := ca.Load(dir, nil); !errors.Is(err, ca.ErrWaitingForIntermediate) {
		t.Fatalf("Load before the import: %v, want ErrWaitingForIntermediate", err)
	}
	cert := corp.SignSubCA(t, csr, catest.SubCAOptions{})
	// The chain may come in any order and with extra certificates.
	unrelated := catest.NewCorp(t).Root
	if err := ca.ImportIntermediate(dir, ca.ImportOptions{Cert: cert, Chain: []*x509.Certificate{unrelated, corp.Issuing}, Root: corp.Root}); err != nil {
		t.Fatal(err)
	}
	authority, err := ca.Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if chain := authority.Chain(); len(chain) != 2 || !chain[1].Equal(corp.Issuing) {
		t.Fatalf("chain = %d certificates, want the intermediate and the issuing CA", len(chain))
	}
	if !authority.RootCert().Equal(corp.Root) {
		t.Error("the root is not the company's")
	}

	// A certificate from it is accepted by a machine that trusts only the
	// company root.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf, err := authority.IssueX509(ca.X509Request{Template: ca.TLSServer, PublicKey: key.Public(), DNSNames: []string{"web.corp.example"}})
	if err != nil {
		t.Fatal(err)
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(corp.Root)
	for _, c := range authority.Chain() {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "web.corp.example"}); err != nil {
		t.Errorf("a machine that trusts the company root refuses it: %v", err)
	}
	// The CRL is signed by BastionXP CA's intermediate, which may sign CRLs.
	if _, err := authority.SignCRL(nil); err != nil {
		t.Error(err)
	}
}

// Importing an intermediate is refused when it is not a CA, cannot sign
// CRLs, chains to another root, lacks its chain or root, or is for another
// key; after a refusal the CA still waits.
func TestImportRefusals(t *testing.T) {
	corp := catest.NewCorp(t)
	other := catest.NewCorp(t)
	tests := []struct {
		name string
		opts func(t *testing.T, csr []byte) ca.ImportOptions
		want string
	}{
		{"not a CA", func(t *testing.T, csr []byte) ca.ImportOptions {
			return ca.ImportOptions{Cert: corp.SignSubCA(t, csr, catest.SubCAOptions{NotCA: true}), Chain: []*x509.Certificate{corp.Issuing}, Root: corp.Root}
		}, "not a CA certificate"},
		{"cannot sign CRLs", func(t *testing.T, csr []byte) ca.ImportOptions {
			return ca.ImportOptions{Cert: corp.SignSubCA(t, csr, catest.SubCAOptions{NoCRLSign: true}), Chain: []*x509.Certificate{corp.Issuing}, Root: corp.Root}
		}, "cRLSign"},
		{"another root", func(t *testing.T, csr []byte) ca.ImportOptions {
			return ca.ImportOptions{Cert: corp.SignSubCA(t, csr, catest.SubCAOptions{}), Chain: []*x509.Certificate{corp.Issuing}, Root: other.Root}
		}, "does not chain up"},
		{"chain missing", func(t *testing.T, csr []byte) ca.ImportOptions {
			return ca.ImportOptions{Cert: corp.SignSubCA(t, csr, catest.SubCAOptions{}), Root: corp.Root}
		}, "does not chain up"},
		{"no root", func(t *testing.T, csr []byte) ca.ImportOptions {
			return ca.ImportOptions{Cert: corp.SignSubCA(t, csr, catest.SubCAOptions{}), Chain: []*x509.Certificate{corp.Issuing}}
		}, "root certificate"},
		{"for another key", func(t *testing.T, _ []byte) ca.ImportOptions {
			_, otherCSR := externalCA(t)
			return ca.ImportOptions{Cert: corp.SignSubCA(t, otherCSR, catest.SubCAOptions{}), Chain: []*x509.Certificate{corp.Issuing}, Root: corp.Root}
		}, "not for the key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, csr := externalCA(t)
			err := ca.ImportIntermediate(dir, tt.opts(t, csr))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
			// Nothing changed: still waiting.
			if _, err := ca.Load(dir, nil); !errors.Is(err, ca.ErrWaitingForIntermediate) {
				t.Errorf("after a refused import: %v", err)
			}
		})
	}
}

// Replacing the intermediate under another root: a new CSR, then its
// certificate. The root cannot change.
func TestReplaceUnderAnotherRoot(t *testing.T) {
	corp := catest.NewCorp(t)
	dir, csr := externalCA(t)
	first := corp.SignSubCA(t, csr, catest.SubCAOptions{ByRoot: true})
	if err := ca.ImportIntermediate(dir, ca.ImportOptions{Cert: first, Root: corp.Root}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ca.ChainFile)); !errors.Is(err, os.ErrNotExist) {
		t.Error("a chain file although the root signed the intermediate directly")
	}

	next, err := ca.NewIntermediateCSR(dir, ca.IntermediateCSROptions{Name: "Zero", Organization: "Corp", KeyType: ca.KeyTypeECDSA})
	if err != nil {
		t.Fatal(err)
	}
	// The CA keeps working with the current one meanwhile.
	if _, err := ca.Load(dir, nil); err != nil {
		t.Fatal(err)
	}
	if err := ca.ImportIntermediate(dir, ca.ImportOptions{Cert: corp.SignSubCA(t, next, catest.SubCAOptions{}),
		Chain: []*x509.Certificate{corp.Issuing}, Root: catest.NewCorp(t).Root}); err == nil || !strings.Contains(err.Error(), "root cannot change") {
		t.Errorf("another root: %v", err)
	}
	second := corp.SignSubCA(t, next, catest.SubCAOptions{})
	if err := ca.ImportIntermediate(dir, ca.ImportOptions{Cert: second, Chain: []*x509.Certificate{corp.Issuing}}); err != nil {
		t.Fatal(err)
	}
	authority, err := ca.Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !authority.IntermediateCert().Equal(second) {
		t.Error("the new intermediate is not in use")
	}
	if kept, _ := filepath.Glob(filepath.Join(dir, ca.ReplacedDir, "*-"+ca.IntermediateCertFile)); len(kept) != 1 {
		t.Errorf("replaced = %v", kept)
	}
}

// The CSR asks for what an intermediate needs.
func TestIntermediateCSR(t *testing.T) {
	_, csrPEM := externalCA(t)
	certs, err := ca.ParseCerts(csrPEM)
	if err == nil || certs != nil {
		t.Fatal("a CSR read as a certificate")
	}
	if !strings.Contains(string(csrPEM), "CERTIFICATE REQUEST") {
		t.Fatalf("not a PEM CSR: %s", csrPEM)
	}
}
