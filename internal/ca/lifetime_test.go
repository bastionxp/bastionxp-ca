// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/keyfile"
)

// lifetimeOf is a CA certificate's lifetime, without the minute it is
// backdated by.
func lifetimeOf(cert *x509.Certificate) time.Duration {
	return cert.NotAfter.Sub(cert.NotBefore) - backdate
}

// By default the root lives 10 years and the intermediate 3.
func TestDefaultLifetimes(t *testing.T) {
	authority := newTestCA(t)
	if got := lifetimeOf(authority.RootCert()); got != 10*365*day {
		t.Errorf("root lifetime %v, want 10 years", got)
	}
	if got := lifetimeOf(authority.IntermediateCert()); got != 3*365*day {
		t.Errorf("intermediate lifetime %v, want 3 years", got)
	}
}

// Configured root and intermediate lifetimes are used; an intermediate that
// would outlive the root is refused at init.
func TestConfiguredLifetimes(t *testing.T) {
	dir := t.TempDir()
	opts := testOptions
	opts.RootValidity, opts.IntermediateValidity = 2*365*day, 400*day
	if err := Init(dir, opts); err != nil {
		t.Fatal(err)
	}
	authority, err := Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := lifetimeOf(authority.RootCert()); got != 2*365*day {
		t.Errorf("root lifetime %v, want 2 years", got)
	}
	if got := lifetimeOf(authority.IntermediateCert()); got != 400*day {
		t.Errorf("intermediate lifetime %v, want 400 days", got)
	}

	// An intermediate longer than the root is refused at init.
	opts.IntermediateValidity = 3 * 365 * day
	if err := Init(t.TempDir(), opts); err == nil {
		t.Error("init made an intermediate that outlives the root")
	}
}

// A replacement intermediate that would outlive the root is refused, not
// shortened, and nothing changes; with a shorter lifetime it is made.
func TestReplacementMayNotOutliveTheRoot(t *testing.T) {
	dir := t.TempDir()
	opts := testOptions
	opts.RootValidity, opts.IntermediateValidity = 2*365*day, 365*day
	if err := Init(dir, opts); err != nil {
		t.Fatal(err)
	}
	rootKey, err := keyfile.Read(filepath.Join(dir, RootKeyFile), nil)
	if err != nil {
		t.Fatal(err)
	}
	replace := ReplaceOptions{Name: "Test", Organization: "Test Org", KeyType: KeyTypeECDSA, RootKey: rootKey}

	// The default, 3 years, would outlive a 2-year root: refused, not
	// quietly shortened, and nothing changes.
	before, _ := readCert(filepath.Join(dir, IntermediateCertFile))
	if _, err := ReplaceIntermediate(dir, replace); !errors.Is(err, ErrOutlivesRoot) {
		t.Fatalf("error = %v, want ErrOutlivesRoot", err)
	}
	if after, _ := readCert(filepath.Join(dir, IntermediateCertFile)); !after.Equal(before) {
		t.Error("the intermediate changed although the replacement was refused")
	}

	replace.Validity = 500 * day
	cert, err := ReplaceIntermediate(dir, replace)
	if err != nil {
		t.Fatal(err)
	}
	if got := lifetimeOf(cert); got != 500*day {
		t.Errorf("new intermediate lifetime %v, want 500 days", got)
	}
}

// The built-in profiles are short-lived; custom profiles are for anything
// longer.
func TestBuiltInLifetimes(t *testing.T) {
	for _, c := range []struct {
		name     string
		def, max time.Duration
	}{
		{"tls-server", 24 * time.Hour, 30 * day},
		{"tls-client", 24 * time.Hour, 30 * day},
		{"tls-device", 30 * day, 90 * day},
	} {
		tmpl, ok := X509TemplateByName(c.name)
		if !ok || tmpl.DefaultValidity != c.def || tmpl.MaxValidity != c.max {
			t.Errorf("%s: %s / max %s, want %s / max %s", c.name, tmpl.DefaultValidity, tmpl.MaxValidity, c.def, c.max)
		}
	}
	for _, c := range []struct {
		name     string
		def, max time.Duration
	}{
		{"ssh-user", 16 * time.Hour, 24 * time.Hour},
		{"ssh-host", 30 * day, 90 * day},
	} {
		tmpl, ok := SSHTemplateByName(c.name)
		if !ok || tmpl.DefaultValidity != c.def || tmpl.MaxValidity != c.max {
			t.Errorf("%s: %s / max %s, want %s / max %s", c.name, tmpl.DefaultValidity, tmpl.MaxValidity, c.def, c.max)
		}
	}
	if TLSDevice.Base != "tls-client" {
		t.Errorf("tls-device base %q, want tls-client", TLSDevice.Base)
	}
}
