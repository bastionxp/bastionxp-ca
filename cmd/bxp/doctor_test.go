// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
	"github.com/bastionxp/bastionxp-ca/internal/store"
)

func doctor(t *testing.T, cfg *config.Config) (*report, string) {
	t.Helper()
	var out bytes.Buffer
	r := runDoctor(context.Background(), &out, cfg)
	return r, out.String()
}

func wantLine(t *testing.T, output, level, text string) {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), level) && strings.Contains(line, text) {
			return
		}
	}
	t.Errorf("no %q line with %q in:\n%s", level, text, output)
}

// A running CA with a login and a public address: nothing fails.
func TestDoctorHealthy(t *testing.T) {
	testCA := startTestCA(t, withPublicHTTP)
	testCA.issueTLS(t, "web.example.com")
	r, out := doctor(t, testCA.cfg)
	if r.fails != 0 {
		t.Fatalf("%d failures:\n%s", r.fails, out)
	}
	wantLine(t, out, "ok", "the server answers at "+testCA.url)
	wantLine(t, out, "ok", "the public address serves this CA's root")
	wantLine(t, out, "ok", "the identity provider answers")
	wantLine(t, out, "ok", "the database is intact")
	wantLine(t, out, "warn", "the root key is in data_dir")
}

// bxp doctor finds a missing key, a damaged database, open file permissions,
// an unreachable identity provider and a server that is not running.
func TestDoctorFindsProblems(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, cfg *config.Config)
		level string
		text  string
	}{
		{"missing key", func(t *testing.T, cfg *config.Config) {
			os.Remove(filepath.Join(cfg.DataDir, ca.SSHHostCAKeyFile))
		}, "FAIL", "ssh_host_ca.key is missing"},
		{"damaged database", func(t *testing.T, cfg *config.Config) {
			os.WriteFile(filepath.Join(cfg.DataDir, store.FileName), []byte("not a database, just some bytes"), 0o600)
		}, "FAIL", "database"},
		{"open permissions", func(t *testing.T, cfg *config.Config) {
			os.Chmod(filepath.Join(cfg.DataDir, ca.IntermediateKeyFile), 0o644)
		}, "warn", "readable by others"},
		{"identity provider unreachable", func(t *testing.T, cfg *config.Config) {
			cfg.OIDC = config.OIDC{Issuer: "http://127.0.0.1:1/nowhere", ClientID: "id", ClientSecret: "s"}
		}, "FAIL", "the identity provider cannot be reached"},
		{"server not running", func(t *testing.T, cfg *config.Config) {
			cfg.Server.URL = "https://127.0.0.1:1"
		}, "warn", "the server does not answer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Only initialized, not served: the server would read the
			// files the setup breaks.
			cfg := newTestConfig(t)
			if err := runInit(io.Discard, cfg, testInit); err != nil {
				t.Fatal(err)
			}
			db, err := store.Open(filepath.Join(cfg.DataDir, store.FileName))
			if err != nil {
				t.Fatal(err)
			}
			db.Close()
			tt.setup(t, cfg)
			_, out := doctor(t, cfg)
			wantLine(t, out, tt.level, tt.text)
		})
	}
}

// bxp doctor with encrypted keys warns when no passphrase is configured,
// checks that the keys open with the configured one, and fails when it is
// wrong.
func TestDoctorEncryptedKeys(t *testing.T) {
	cfg := initEncrypted(t)
	_, out := doctor(t, cfg)
	wantLine(t, out, "warn", "no passphrase is configured")

	t.Setenv(envKeyPassphrase, testKeyPassphrase)
	r, out := doctor(t, cfg)
	wantLine(t, out, "ok", "passphrase from "+envKeyPassphrase)
	wantLine(t, out, "ok", "the keys open")
	if r.fails != 0 {
		t.Errorf("failures:\n%s", out)
	}

	t.Setenv(envKeyPassphrase, "not the passphrase")
	_, out = doctor(t, cfg)
	wantLine(t, out, "FAIL", "the CA keys do not open")
}

// bxp doctor checks that the directory accepts the CA's service account, and
// fails with a wrong password.
func TestDoctorLDAP(t *testing.T) {
	testCA := startLDAPTestCA(t)
	_, out := doctor(t, testCA.cfg)
	wantLine(t, out, "ok", "the directory accepts the CA's service account")

	cfg := *testCA.cfg
	cfg.LDAP.BindPasswordFile = writeSecret(t, "wrong")
	_, out = doctor(t, &cfg)
	wantLine(t, out, "FAIL", "the directory does not accept the CA")
}

// No CA at all: one clear failure, nothing else.
func TestDoctorWithoutCA(t *testing.T) {
	r, out := doctor(t, newTestConfig(t))
	if r.fails != 1 {
		t.Errorf("failures = %d, want 1:\n%s", r.fails, out)
	}
	wantLine(t, out, "FAIL", "there is no CA")
}
