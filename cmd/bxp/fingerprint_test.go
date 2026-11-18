// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
)

// bxp fingerprint prints only the root fingerprint on standard output, and a
// bxp trust hint with the server's URL when it is set.
func TestFingerprint(t *testing.T) {
	cfg := newTestConfig(t)
	if err := runInit(io.Discard, cfg, testInit); err != nil {
		t.Fatal(err)
	}
	authority, err := ca.Load(cfg.DataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := ca.CertFingerprint(authority.RootCert())

	var out, hints bytes.Buffer
	if err := runFingerprint(&out, &hints, cfg); err != nil {
		t.Fatal(err)
	}
	// Only the fingerprint on the normal output, for scripts.
	if got := out.String(); got != want+"\n" {
		t.Errorf("output = %q, want the fingerprint alone", got)
	}
	if !strings.Contains(hints.String(), "bxp trust --ca-url <address of this server> --fingerprint "+want) {
		t.Errorf("hint:\n%s", hints.String())
	}

	// With server.url set, the hint has the real address.
	cfg.Server.URL = "https://ca.example.com:8443"
	hints.Reset()
	if err := runFingerprint(io.Discard, &hints, cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hints.String(), "--ca-url https://ca.example.com:8443 ") {
		t.Errorf("hint:\n%s", hints.String())
	}
}

// The root key is meant to be moved offline after "bxp init", and the
// other keys may not be readable. The fingerprint needs none of them.
func TestFingerprintNeedsNoKeys(t *testing.T) {
	cfg := newTestConfig(t)
	if err := runInit(io.Discard, cfg, testInit); err != nil {
		t.Fatal(err)
	}
	keys, _ := filepath.Glob(filepath.Join(cfg.DataDir, "*.key"))
	for _, key := range keys {
		if err := os.Remove(key); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := runFingerprint(&out, io.Discard, cfg); err != nil {
		t.Fatalf("without the keys: %v", err)
	}
	if len(strings.TrimSpace(out.String())) != 64 {
		t.Errorf("output = %q", out.String())
	}
}

// bxp fingerprint without a CA says the root certificate is missing.
func TestFingerprintWithoutACA(t *testing.T) {
	cfg := newTestConfig(t) // never initialised
	if err := runFingerprint(io.Discard, io.Discard, cfg); err == nil || !strings.Contains(err.Error(), "root certificate") {
		t.Errorf("error = %v, want one about the missing root certificate", err)
	}
}
