// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/keyfile"
)

// With passphrases, the root key goes only to its offline place, encrypted
// with the root passphrase; the server's keys are encrypted with their own
// passphrase, and the CA loads only with that one.
func TestInitWithEncryptedKeys(t *testing.T) {
	dir := t.TempDir()
	offline := filepath.Join(t.TempDir(), "usb", "root.key")
	if err := os.MkdirAll(filepath.Dir(offline), 0o700); err != nil {
		t.Fatal(err)
	}
	opts := testOptions
	opts.RootPassphrase = []byte("root passphrase!")
	opts.KeyPassphrase = []byte("server passphrase")
	opts.RootKeyPath = offline
	if err := Init(dir, opts); err != nil {
		t.Fatal(err)
	}

	// The root key went only to the offline place, encrypted.
	if _, err := os.Stat(filepath.Join(dir, RootKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("root key in data_dir: %v", err)
	}
	if _, err := keyfile.Read(offline, nil); !errors.Is(err, keyfile.ErrPassphraseNeeded) {
		t.Errorf("root key without passphrase: %v, want ErrPassphraseNeeded", err)
	}
	if _, err := keyfile.Read(offline, opts.RootPassphrase); err != nil {
		t.Errorf("root key: %v", err)
	}
	// The server's keys are encrypted with their own passphrase.
	for _, file := range []string{IntermediateKeyFile, SSHUserCAKeyFile, SSHHostCAKeyFile} {
		if encrypted, err := keyfile.IsEncrypted(filepath.Join(dir, file)); err != nil || !encrypted {
			t.Errorf("%s: encrypted = %v, %v", file, encrypted, err)
		}
	}

	if _, err := Load(dir, nil); !errors.Is(err, keyfile.ErrPassphraseNeeded) {
		t.Errorf("Load without passphrase: %v, want ErrPassphraseNeeded", err)
	}
	if _, err := Load(dir, opts.RootPassphrase); !errors.Is(err, keyfile.ErrWrongPassphrase) {
		t.Errorf("Load with the root passphrase: %v, want ErrWrongPassphrase", err)
	}
	if _, err := Load(dir, opts.KeyPassphrase); err != nil {
		t.Errorf("Load: %v", err)
	}
}

// An existing root key is never overwritten, and a refused Init leaves
// nothing behind.
func TestInitKeepsAnExistingRootKey(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(t.TempDir(), "root.key")
	if err := os.WriteFile(existing, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := testOptions
	opts.RootKeyPath = existing
	if err := Init(dir, opts); err == nil {
		t.Fatal("no error")
	}
	if data, _ := os.ReadFile(existing); string(data) != "precious" {
		t.Error("the existing root key was changed")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("data_dir is not empty: %v", entries)
	}
}
