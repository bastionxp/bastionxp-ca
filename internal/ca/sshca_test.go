// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Replacing the SSH user CA key in two steps: the next key is published
// beside the current one, which still signs; only one next key may wait, and
// only for that CA; activating without a next key is refused; after
// activation the new key signs, the old private key is gone, and its public
// key is kept.
func TestSSHCAReplacement(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, testOptions); err != nil {
		t.Fatal(err)
	}
	before, err := Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := before.SSHUserCAPublicKey()
	oldFile, _ := os.ReadFile(filepath.Join(dir, SSHUserCAKeyFile))

	// Step 1: the next key. Published next to the current one, but the
	// current one still signs.
	next, err := NewSSHCA(dir, SSHUserCA, NewSSHCAOptions{Name: "Test", KeyType: KeyTypeECDSA})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSSHCA(dir, SSHUserCA, NewSSHCAOptions{Name: "Test", KeyType: KeyTypeECDSA}); err == nil {
		t.Error("a second next key was made")
	}
	during, err := Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if keys := during.SSHUserCAPublicKeys(); len(keys) != 2 || !bytes.Equal(keys[1].Marshal(), next.Marshal()) {
		t.Fatalf("published keys = %d, want the current and the next", len(keys))
	}
	if len(during.SSHHostCAPublicKeys()) != 1 {
		t.Error("the host CA has a next key it should not have")
	}
	cert, err := during.IssueSSH(sshTestRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), oldKey.Marshal()) {
		t.Error("the next key signed before it was activated")
	}

	// Step 2: activate.
	if _, err := ActivateSSHCA(dir, SSHUserCA, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ActivateSSHCA(dir, SSHUserCA, nil); err == nil {
		t.Error("activated without a next key")
	}
	after, err := Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if keys := after.SSHUserCAPublicKeys(); len(keys) != 1 || !bytes.Equal(keys[0].Marshal(), next.Marshal()) {
		t.Error("the next key is not the current one")
	}
	cert, err = after.IssueSSH(sshTestRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), next.Marshal()) {
		t.Error("not signed with the new key")
	}
	// The old private key is gone; its public key is kept.
	if now, _ := os.ReadFile(filepath.Join(dir, SSHUserCAKeyFile)); bytes.Equal(now, oldFile) {
		t.Error("the old key file is still in place")
	}
	if kept, _ := filepath.Glob(filepath.Join(dir, ReplacedDir, "*-"+SSHUserCAPubFile)); len(kept) != 1 {
		t.Errorf("replaced public keys = %v", kept)
	}
}

// Host certificates signed with a replaced host key can still be renewed.
func TestReplacedHostCAKeyIsOwn(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, testOptions); err != nil {
		t.Fatal(err)
	}
	before, _ := Load(dir, nil)
	old := before.SSHHostCAPublicKey()
	if _, err := NewSSHCA(dir, SSHHostCA, NewSSHCAOptions{Name: "Test", KeyType: KeyTypeECDSA}); err != nil {
		t.Fatal(err)
	}
	if _, err := ActivateSSHCA(dir, SSHHostCA, nil); err != nil {
		t.Fatal(err)
	}
	after, err := Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !after.IsOwnSSHHostCA(old) || !after.IsOwnSSHHostCA(after.SSHHostCAPublicKey()) {
		t.Error("the old or the new host CA key is not recognized")
	}
	if after.IsOwnSSHHostCA(after.SSHUserCAPublicKey()) {
		t.Error("the user CA key passes as a host CA key")
	}
}
