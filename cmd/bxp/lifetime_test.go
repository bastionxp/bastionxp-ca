// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/x509"
	"io"
	"strings"
	"testing"
	"time"
)

// How early the CA warns that a CA certificate will expire: a fifth of its
// lifetime, at most a year.
func TestExpiryWarning(t *testing.T) {
	const year = 365 * 24 * time.Hour
	now := time.Now()
	for _, tt := range []struct {
		lifetime time.Duration
		want     time.Duration
	}{
		{3 * year, 3 * year / 5}, // about 7 months
		{5 * year, year},         // a fifth: exactly the maximum
		{10 * year, year},        // capped
		{year, year / 5},
	} {
		cert := &x509.Certificate{NotBefore: now, NotAfter: now.Add(tt.lifetime)}
		if got := expiryWarning(cert, intermediateWarningMax); got != tt.want {
			t.Errorf("lifetime %v: warning %v, want %v", tt.lifetime, got, tt.want)
		}
	}
}

// Under an external root, the root's CA decides the intermediate's
// lifetime: a setting for it would do nothing, so it is refused.
func TestIntermediateValidityRefusedUnderExternalRoot(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.CA.IntermediateValidity = "5y"
	err := runInitExternal(io.Discard, cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "does not apply under an external root") {
		t.Errorf("error = %v", err)
	}
}

// doctor says when the configuration's lifetimes differ from the
// certificates', and that they apply only when a certificate is made.
func TestDoctorLifetimes(t *testing.T) {
	cfg := newTestConfig(t)
	if err := runInit(io.Discard, cfg, testInit); err != nil {
		t.Fatal(err)
	}
	_, out := doctor(t, cfg)
	if strings.Contains(out, "ca.root_validity") || strings.Contains(out, "the next one") {
		t.Errorf("doctor reports a difference where there is none:\n%s", out)
	}

	cfg.CA.RootValidity = "20y"
	cfg.CA.IntermediateValidity = "5y"
	_, out = doctor(t, cfg)
	wantLine(t, out, "warn", "the root is valid for 10y, but ca.root_validity says 20y")
	wantLine(t, out, "ok", "the intermediate is valid for 3y; the next one (bxp new-intermediate) will be for 5y")
}
