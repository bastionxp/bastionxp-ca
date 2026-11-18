// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
)

// With name constraints, names inside them are issued and names outside are
// refused even when the token allows them; bxp doctor shows the constraints
// and warns when the configuration changed; a new intermediate takes the
// configured ones.
func TestNameConstraints(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.CA.NameConstraints = config.NameConstraints{DNSDomains: []string{"example.com", "localhost"}, IPRanges: []string{"127.0.0.0/8"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := runInit(io.Discard, cfg, testInit); err != nil {
		t.Fatal(err)
	}
	url := serveForTest(t, cfg)
	testCA := &testCA{cfg: cfg, url: url, root: filepath.Join(cfg.DataDir, ca.RootCertFile)}

	// Inside: issued. (The server's own certificate, for localhost and
	// 127.0.0.1, was issued too, or nothing would answer.)
	if leaf, _ := testCA.issueTLS(t, "web.example.com"); !slices.Equal(leaf.DNSNames, []string{"web.example.com"}) {
		t.Errorf("names %v", leaf.DNSNames)
	}
	// Outside: refused, although the token allows it.
	conn := testCA.connection(t, "tls-server", "web.other.com")
	err := runTLS(context.Background(), io.Discard, conn, tlsOptions{names: []string{"web.other.com"}, outDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "name constraints") {
		t.Errorf("error = %v, want a refusal for the name constraints", err)
	}

	// doctor shows them, and warns when the configuration has changed.
	_, out := doctor(t, cfg)
	wantLine(t, out, "ok", "name constraints")
	changed := *cfg
	changed.CA.NameConstraints = config.NameConstraints{DNSDomains: []string{"example.com", "localhost", "example.org"}, IPRanges: []string{"127.0.0.0/8"}}
	_, out = doctor(t, &changed)
	wantLine(t, out, "warn", "name constraints differ")

	// A new intermediate takes the constraints of the configuration.
	rootKey := filepath.Join(cfg.DataDir, ca.RootKeyFile)
	if err := runNewIntermediate(context.Background(), io.Discard, io.Discard, &changed, replaceWith(rootKey, testInit.rootPassphrase, true)); err != nil {
		t.Fatal(err)
	}
	keys, err := loadServerKeys(&changed, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := keys.ca.IntermediateCert().PermittedDNSDomains; !slices.Contains(got, "example.org") {
		t.Errorf("new intermediate's DNS constraints = %v", got)
	}
}
