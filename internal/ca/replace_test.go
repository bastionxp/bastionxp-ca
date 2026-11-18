// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"path/filepath"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/keyfile"
)

// After a new intermediate, Load knows the replaced one, so that the
// certificates it issued can still be renewed.
func TestReplacedIntermediatesAreLoaded(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, testOptions); err != nil {
		t.Fatal(err)
	}
	rootKey, err := keyfile.Read(filepath.Join(dir, RootKeyFile), nil)
	if err != nil {
		t.Fatal(err)
	}
	old, err := readCert(filepath.Join(dir, IntermediateCertFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReplaceIntermediate(dir, ReplaceOptions{Name: "Test", Organization: "Test Org", KeyType: KeyTypeECDSA, RootKey: rootKey}); err != nil {
		t.Fatal(err)
	}

	authority, err := Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authority.IntermediateCert().Equal(old) {
		t.Fatal("the intermediate was not replaced")
	}
	replaced := authority.ReplacedIntermediates()
	if len(replaced) != 1 || !replaced[0].Equal(old) {
		t.Errorf("replaced intermediates: %d, want the old one", len(replaced))
	}
}
