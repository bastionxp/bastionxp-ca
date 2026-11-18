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
	"slices"
	"strings"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
)

// A profile of the administrator's own, used like a built-in template.
func TestProfileEndToEnd(t *testing.T) {
	testCA := startTestCA(t, func(cfg *config.Config) {
		var deviceClient config.Profile
		deviceClient.Name, deviceClient.Base, deviceClient.Validity = "device-client", "tls-client", "365d"
		deviceClient.Subject.OrganizationalUnit = []string{"Devices"}
		cfg.Profiles = []config.Profile{deviceClient}
	})
	if err := testCA.cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	conn := testCA.connection(t, "device-client", "laptop-1.example.com")
	outDir := t.TempDir()
	if err := runTLS(context.Background(), io.Discard, conn, tlsOptions{names: []string{"laptop-1.example.com"}, outDir: outDir}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "laptop-1.example.com.crt"))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := ca.ParseCerts(data)
	if err != nil {
		t.Fatal(err)
	}
	leaf := certs[0]
	if !slices.Equal(leaf.Subject.OrganizationalUnit, []string{"Devices"}) ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("OU %v, usage %v", leaf.Subject.OrganizationalUnit, leaf.ExtKeyUsage)
	}
	if days := leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24; days < 364 {
		t.Errorf("lifetime %.0f days, want the profile's 365", days)
	}

	// "bxp profiles" shows what it ends up with.
	var shown bytes.Buffer
	if err := runProfiles(&shown, testCA.cfg, "device-client"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"device-client  (profile, base tls-client)", "client auth", "365 days (max 365 days)", "OU=Devices"} {
		if !strings.Contains(shown.String(), want) {
			t.Errorf("profiles output lacks %q:\n%s", want, shown.String())
		}
	}
	shown.Reset()
	if err := runProfiles(&shown, testCA.cfg, ""); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tls-server", "tls-client", "tls-device", "ssh-user", "ssh-host", "device-client"} {
		if !strings.Contains(shown.String(), name+"  (") {
			t.Errorf("the list lacks %s", name)
		}
	}
	if err := runProfiles(io.Discard, testCA.cfg, "nope"); err == nil || !strings.Contains(err.Error(), "device-client") {
		t.Errorf("unknown name: %v", err)
	}

	// An unknown template name is refused before a token is made.
	var out bytes.Buffer
	err = runToken(&out, testCA.cfg, tokenOptions{template: "device-client-typo", names: []string{"x"}})
	if err == nil || !strings.Contains(err.Error(), "profile") {
		t.Errorf("unknown template: %v", err)
	}
}
