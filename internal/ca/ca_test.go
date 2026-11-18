// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"bytes"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

var testOptions = InitOptions{Name: "Test", Organization: "Test Org", KeyType: KeyTypeECDSA}

// newTestCA creates a fresh CA in a temporary directory and loads it.
func newTestCA(t *testing.T) *CA {
	t.Helper()
	dir := t.TempDir()
	if err := Init(dir, testOptions); err != nil {
		t.Fatalf("Init: %v", err)
	}
	authority, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return authority
}

// verifyChain checks that cert chains up to the CA's root for the given usage.
func verifyChain(t *testing.T, authority *CA, cert *x509.Certificate, opts x509.VerifyOptions) {
	t.Helper()
	opts.Roots = x509.NewCertPool()
	opts.Roots.AddCert(authority.RootCert())
	opts.Intermediates = x509.NewCertPool()
	opts.Intermediates.AddCert(authority.IntermediateCert())
	opts.CurrentTime = authority.now()
	if _, err := cert.Verify(opts); err != nil {
		t.Fatalf("certificate does not verify: %v", err)
	}
}

// A CA made with ECDSA or RSA keys loads again: a root and an intermediate,
// both CA certificates, the intermediate chaining to the root with path
// length 0.
func TestInitAndLoad(t *testing.T) {
	for _, keyType := range []string{KeyTypeECDSA, KeyTypeRSA} {
		t.Run(keyType, func(t *testing.T) {
			if keyType == KeyTypeRSA && testing.Short() {
				t.Skip("RSA key generation is slow")
			}
			dir := t.TempDir()
			opts := testOptions
			opts.KeyType = keyType
			if err := Init(dir, opts); err != nil {
				t.Fatalf("Init: %v", err)
			}
			authority, err := Load(dir, nil)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}

			root := authority.RootCert()
			if root.Subject.CommonName != "Test Root CA" {
				t.Errorf("root CN = %q", root.Subject.CommonName)
			}
			if !root.IsCA || !authority.IntermediateCert().IsCA {
				t.Error("root and intermediate must be CA certificates")
			}
			// The intermediate must chain to the root and must not be able
			// to create further CAs below it.
			verifyChain(t, authority, authority.IntermediateCert(), x509.VerifyOptions{})
			if !authority.IntermediateCert().MaxPathLenZero {
				t.Error("intermediate must have path length 0")
			}
		})
	}
}

// Creating a CA where one exists is refused, and the existing root is
// unchanged.
func TestInitRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, testOptions); err != nil {
		t.Fatalf("first Init: %v", err)
	}
	before, err := os.ReadFile(filepath.Join(dir, RootCertFile))
	if err != nil {
		t.Fatal(err)
	}

	err = Init(dir, testOptions)
	if !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second Init error = %v, want ErrAlreadyInitialized", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, RootCertFile))
	if !bytes.Equal(before, after) {
		t.Error("second Init changed the root certificate")
	}
}

// Every private key file of a new CA has mode 600.
func TestInitFilePermissions(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, testOptions); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{RootKeyFile, IntermediateKeyFile, SSHUserCAKeyFile, SSHHostCAKeyFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s has permissions %o, want 600", name, perm)
		}
	}
}

// A new CA writes the SSH user and host CA public keys as public key lines,
// matching the loaded keys, and the two keys differ.
func TestInitWritesSSHPublicKeys(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, testOptions); err != nil {
		t.Fatal(err)
	}
	authority, err := Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, SSHUserCAPubFile))
	if err != nil {
		t.Fatal(err)
	}
	pub, comment, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		t.Fatalf("ssh_user_ca.pub is not a valid public key line: %v", err)
	}
	if comment != "Test SSH User CA" {
		t.Errorf("comment = %q", comment)
	}
	if !bytes.Equal(pub.Marshal(), authority.SSHUserCAPublicKey().Marshal()) {
		t.Error("ssh_user_ca.pub does not match the loaded SSH user CA key")
	}
	if bytes.Equal(authority.SSHUserCAPublicKey().Marshal(), authority.SSHHostCAPublicKey().Marshal()) {
		t.Error("user and host CA keys must be different")
	}
}

// Loading a CA whose intermediate key belongs to another CA fails.
func TestLoadRejectsMismatchedKey(t *testing.T) {
	dir, otherDir := t.TempDir(), t.TempDir()
	if err := Init(dir, testOptions); err != nil {
		t.Fatal(err)
	}
	if err := Init(otherDir, testOptions); err != nil {
		t.Fatal(err)
	}
	// Replace the intermediate key with the key of another CA.
	otherKey, err := os.ReadFile(filepath.Join(otherDir, IntermediateKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, IntermediateKeyFile), otherKey, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(dir, nil); err == nil {
		t.Fatal("Load accepted an intermediate key that does not match the certificate")
	}
}

// The CA loads and works with the root key offline.
func TestLoadWithoutRootKey(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, testOptions); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, RootKeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, nil); err != nil {
		t.Fatalf("Load must work with the root key offline: %v", err)
	}
}
