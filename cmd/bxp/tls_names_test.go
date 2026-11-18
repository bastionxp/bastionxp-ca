// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// With --token and no --name, "bxp tls" asks for every name the token
// allows, as "bxp ssh" does with principals.
func TestTLSNamesFromToken(t *testing.T) {
	testCA := startTestCA(t)
	conn := testCA.connection(t, "tls-server", "web.example.com", "10.0.0.5")
	out := t.TempDir()
	if err := runTLS(context.Background(), io.Discard, conn, tlsOptions{outDir: out}); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(out, "web.example.com.crt"), filepath.Join(out, "web.example.com.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	if !slices.Equal(leaf.DNSNames, []string{"web.example.com"}) || len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "10.0.0.5" {
		t.Errorf("names %v %v, want web.example.com and 10.0.0.5", leaf.DNSNames, leaf.IPAddresses)
	}

	// Not a token: say to give the names.
	conn.token = "not-a-token"
	err = runTLS(context.Background(), io.Discard, conn, tlsOptions{outDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "--name") {
		t.Errorf("unreadable token: error = %v, want one asking for --name", err)
	}
}
