// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// SSH key fingerprints are SHA256:, the same for the same key whatever its
// comment, and different for different keys.
func TestSSHFingerprint(t *testing.T) {
	key := newSSHKey(t)
	other := newSSHKey(t)

	got := SSHFingerprint(key)
	if !strings.HasPrefix(got, "SHA256:") {
		t.Errorf("fingerprint = %q, want it to start with SHA256:", got)
	}
	if got != SSHFingerprint(key) {
		t.Error("the same key gave two different fingerprints")
	}
	if got == SSHFingerprint(other) {
		t.Error("two different keys have the same fingerprint")
	}

	// The comment in a .pub file is not part of the key.
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + " alice@laptop"
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if SSHFingerprint(parsed) != got {
		t.Error("the fingerprint changed with the comment")
	}
}

// Public key fingerprints are SHA256:, the same for the same key, different
// for different keys; something that is not a key is an error.
func TestX509Fingerprint(t *testing.T) {
	key := newLeafKey(t)
	other := newLeafKey(t)

	got, err := X509Fingerprint(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "SHA256:") {
		t.Errorf("fingerprint = %q, want it to start with SHA256:", got)
	}
	again, _ := X509Fingerprint(key.Public())
	if got != again {
		t.Error("the same key gave two different fingerprints")
	}
	otherPrint, _ := X509Fingerprint(other.Public())
	if got == otherPrint {
		t.Error("two different keys have the same fingerprint")
	}

	if _, err := X509Fingerprint("not a key"); err == nil {
		t.Error("expected an error for something that is not a key, got nil")
	}
}

// Certificate fingerprints are 64 lower-case hex digits, different for
// different certificates.
func TestCertFingerprint(t *testing.T) {
	authority := newTestCA(t)
	got := CertFingerprint(authority.RootCert())
	if len(got) != 64 || strings.ToLower(got) != got {
		t.Errorf("fingerprint = %q, want 64 lower-case hex digits", got)
	}
	if got == CertFingerprint(authority.IntermediateCert()) {
		t.Error("two certificates have the same fingerprint")
	}
}
