// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/keyfile"
)

func replaceWith(rootKey string, passphrase []byte, yes bool) replaceOptions {
	return replaceOptions{rootKey: rootKey, rootPassphrase: passphrase, yes: yes}
}

// bxp new-intermediate: refused without --yes while certificates are valid,
// and asks; a no changes nothing; after a yes the old key is gone and only
// the old certificate kept; after a restart the new intermediate signs,
// chains to the same root and is served, old certificates still verify, and
// the next change warns only about what the new one issued.
func TestNewIntermediate(t *testing.T) {
	first := startTestCA(t, withPublicHTTP)
	oldLeaf, oldIntermediate := first.issueTLS(t, "old.example.com")
	dataDir := first.cfg.DataDir
	rootKey := filepath.Join(dataDir, ca.RootKeyFile)
	oldKeyFile, err := os.ReadFile(filepath.Join(dataDir, ca.IntermediateKeyFile))
	if err != nil {
		t.Fatal(err)
	}

	// A certificate is still valid: without --yes and nobody to ask,
	// nothing happens.
	err = runNewIntermediate(context.Background(), io.Discard, io.Discard, first.cfg, replaceWith(rootKey, testInit.rootPassphrase, false))
	if err == nil || !strings.Contains(err.Error(), "1 certificate(s)") || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("error = %v, want the warning", err)
	}
	// Asked, and the answer is no.
	no := replaceWith(rootKey, testInit.rootPassphrase, false)
	no.confirm = func(string) (bool, error) { return false, nil }
	if err := runNewIntermediate(context.Background(), io.Discard, io.Discard, first.cfg, no); err == nil {
		t.Fatal("replaced although the answer was no")
	}
	if current, _ := os.ReadFile(filepath.Join(dataDir, ca.IntermediateKeyFile)); !bytes.Equal(current, oldKeyFile) {
		t.Fatal("the intermediate changed although the change was refused")
	}

	// Asked, and yes.
	yes := replaceWith(rootKey, testInit.rootPassphrase, false)
	asked := false
	yes.confirm = func(string) (bool, error) { asked = true; return true, nil }
	if err := runNewIntermediate(context.Background(), io.Discard, io.Discard, first.cfg, yes); err != nil {
		t.Fatal(err)
	}
	if !asked {
		t.Error("not asked")
	}

	// The old key is gone; only the old certificate is kept.
	if current, _ := os.ReadFile(filepath.Join(dataDir, ca.IntermediateKeyFile)); bytes.Equal(current, oldKeyFile) {
		t.Error("the old intermediate key is still in place")
	}
	replaced, _ := os.ReadDir(filepath.Join(dataDir, ca.ReplacedDir))
	if len(replaced) != 1 || !strings.HasSuffix(replaced[0].Name(), ca.IntermediateCertFile) {
		t.Errorf("replaced/ = %v, want only the old certificate", replaced)
	}
	var leftovers []string
	filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && strings.Contains(info.Name(), ".new") {
			leftovers = append(leftovers, path)
		}
		return nil
	})
	if len(leftovers) > 0 {
		t.Errorf("files left behind: %v", leftovers)
	}

	// "Restart": a new server on the same data_dir signs with the new
	// intermediate, which chains to the same root.
	cfg := *first.cfg
	url := serveForTest(t, &cfg)
	second := &testCA{cfg: &cfg, url: url, root: first.root}
	newLeaf, newIntermediate := second.issueTLS(t, "new.example.com")
	if bytes.Equal(newIntermediate.SubjectKeyId, oldIntermediate.SubjectKeyId) {
		t.Fatal("the restarted server signs with the old intermediate")
	}
	rootPEM, err := os.ReadFile(first.root)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(rootPEM)
	// The old certificate still verifies, with the old intermediate it
	// was handed out with.
	for _, pair := range [][2]*x509.Certificate{{oldLeaf, oldIntermediate}, {newLeaf, newIntermediate}} {
		intermediates := x509.NewCertPool()
		intermediates.AddCert(pair[1])
		if _, err := pair[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates}); err != nil {
			t.Errorf("%s: %v", pair[0].Subject.CommonName, err)
		}
	}
	if got := httpGet(t, cfg.Server.PublicURL+ca.IntermediateCertPath); !bytes.Equal(got, ca.EncodeCertPEM(newIntermediate)) {
		t.Error("/intermediate.crt does not serve the new intermediate")
	}

	// Only what the new intermediate issued counts now: the next change
	// warns about the one new certificate, not the old one.
	err = runNewIntermediate(context.Background(), io.Discard, io.Discard, &cfg, replaceWith(rootKey, testInit.rootPassphrase, false))
	if err == nil || !strings.Contains(err.Error(), "1 certificate(s)") {
		t.Errorf("second change: %v, want a warning about the new certificate only", err)
	}
}

// Nothing valid from the current intermediate: no question.
func TestNewIntermediateWithoutCertificates(t *testing.T) {
	testCA := startTestCA(t)
	err := runNewIntermediate(context.Background(), io.Discard, io.Discard, testCA.cfg,
		replaceWith(filepath.Join(testCA.cfg.DataDir, ca.RootKeyFile), testInit.rootPassphrase, false))
	if err != nil {
		t.Fatal(err)
	}
}

// bxp new-intermediate refuses a wrong root passphrase and another root key,
// and changes nothing in the data directory.
func TestNewIntermediateRefusals(t *testing.T) {
	testCA := startTestCA(t)
	rootKey := filepath.Join(testCA.cfg.DataDir, ca.RootKeyFile)

	err := runNewIntermediate(context.Background(), io.Discard, io.Discard, testCA.cfg, replaceWith(rootKey, []byte("not the passphrase"), true))
	if err == nil || !strings.Contains(err.Error(), "wrong passphrase") {
		t.Errorf("wrong passphrase: %v", err)
	}

	other := newTestConfig(t)
	if err := runInit(io.Discard, other, testInit); err != nil {
		t.Fatal(err)
	}
	err = runNewIntermediate(context.Background(), io.Discard, io.Discard, testCA.cfg,
		replaceWith(filepath.Join(other.DataDir, ca.RootKeyFile), testInit.rootPassphrase, true))
	if err == nil || !strings.Contains(err.Error(), "not the key of this CA's root") {
		t.Errorf("another root key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(testCA.cfg.DataDir, ca.ReplacedDir)); err == nil {
		t.Error("a refused change touched data_dir")
	}
}

// With encrypted server keys, the new intermediate key is encrypted with
// the same passphrase.
func TestNewIntermediateWithEncryptedKeys(t *testing.T) {
	cfg := initEncrypted(t)
	t.Setenv(envKeyPassphrase, testKeyPassphrase)
	if err := runNewIntermediate(context.Background(), io.Discard, io.Discard, cfg,
		replaceWith(filepath.Join(cfg.DataDir, ca.RootKeyFile), testInit.rootPassphrase, true)); err != nil {
		t.Fatal(err)
	}
	if encrypted, _ := keyfile.IsEncrypted(filepath.Join(cfg.DataDir, ca.IntermediateKeyFile)); !encrypted {
		t.Error("the new intermediate key is not encrypted")
	}
	t.Setenv(envKeyPassphrase, testKeyPassphrase)
	if _, err := loadServerKeys(cfg, io.Discard); err != nil {
		t.Fatal(err)
	}
}
