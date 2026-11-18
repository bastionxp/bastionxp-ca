// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
)

// reloadEnv is a running server whose configuration is a real file that
// a test can change, and a way to ask the server to reload it.
type reloadEnv struct {
	file   string
	cfg    *config.Config
	url    string
	root   string
	acme   *challengeTarget
	reload chan chan error
	log    *lockedBuffer
}

func (e *reloadEnv) write(t *testing.T, acmeDomains string, extra string) {
	t.Helper()
	content := "data_dir: " + e.cfg.DataDir + "\nca:\n  organization: Test Org\n" +
		"server:\n  address: \"127.0.0.1:0\"\n" +
		"acme:\n  allowed_domains: [" + acmeDomains + "]\n" + extra
	if err := os.WriteFile(e.file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *reloadEnv) doReload(t *testing.T) error {
	t.Helper()
	done := make(chan error, 1)
	select {
	case e.reload <- done:
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not take the reload request")
	}
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not answer the reload request")
	}
	return nil
}

func startReloadEnv(t *testing.T) *reloadEnv {
	t.Helper()
	cfg := newTestConfig(t)
	if err := runInit(io.Discard, cfg, testInit); err != nil {
		t.Fatal(err)
	}
	env := &reloadEnv{
		file:   filepath.Join(t.TempDir(), "bastionxp-ca.yaml"),
		cfg:    cfg,
		root:   filepath.Join(cfg.DataDir, ca.RootCertFile),
		acme:   &challengeTarget{},
		reload: make(chan chan error),
		log:    &lockedBuffer{},
	}
	env.write(t, "example.com", "")
	loaded, err := config.Load(env.file)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	env.url = "https://" + listener.Addr().String()
	hooks := serveHooks{
		ACMEDial: env.acme.dial,
		Reload:   env.reload,
		Load:     func() (*config.Config, error) { return config.Load(env.file) },
	}
	ctx, stop := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- runServe(ctx, loaded, listener, nil, slog.New(slog.NewTextHandler(env.log, nil)), hooks)
	}()
	t.Cleanup(func() {
		stop()
		if err := <-served; err != nil {
			t.Errorf("server stopped with an error: %v", err)
		}
	})
	return env
}

// getACME asks for a certificate for name with ACME, and reports the error.
func (e *reloadEnv) getACME(t *testing.T, name string) error {
	t.Helper()
	address := freeAddress(t)
	e.acme.set(address)
	conn := connection{url: e.url, root: e.root, prompt: io.Discard}
	return runACME(context.Background(), io.Discard, conn, acmeOptions{names: []string{name}, outDir: t.TempDir(), httpAddress: address})
}

// A reload changes the access rules without a restart, and the log says so.
func TestReloadChangesTheRulesWithoutARestart(t *testing.T) {
	env := startReloadEnv(t)

	if err := env.getACME(t, "web.other.org"); err == nil || !strings.Contains(err.Error(), "refused the order") {
		t.Fatalf("before the reload: error = %v, want a refusal", err)
	}

	env.write(t, "example.com, other.org", "")
	if err := env.doReload(t); err != nil {
		t.Fatal(err)
	}
	if err := env.getACME(t, "web.other.org"); err != nil {
		t.Errorf("after the reload: %v", err)
	}
	if !strings.Contains(env.log.String(), "configuration reloaded") {
		t.Errorf("the log does not say so:\n%s", env.log.String())
	}
}

// A broken file must not take the CA down, nor change its rules.
func TestReloadIgnoresABrokenConfiguration(t *testing.T) {
	env := startReloadEnv(t)
	env.write(t, "example.com, other.org", "")
	if err := env.doReload(t); err != nil {
		t.Fatal(err)
	}

	for name, content := range map[string]string{
		"not YAML":    "{{{",
		"unknown key": "data_dir: x\nca:\n  organization: O\nacme:\n  allowd_domains: [evil.com]\n",
		"invalid":     "data_dir: x\nca:\n  organization: O\nacme:\n  allowed_domains: [\"*.evil.com\"]\n",
		"missing":     "",
	} {
		t.Run(name, func(t *testing.T) {
			if content == "" {
				os.Remove(env.file)
			} else if err := os.WriteFile(env.file, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := env.doReload(t); err == nil {
				t.Error("a broken configuration was accepted")
			}
			// The server still runs, with the rules it had.
			if err := env.getACME(t, "web.other.org"); err != nil {
				t.Errorf("the old rules were lost: %v", err)
			}
		})
	}
	if !strings.Contains(env.log.String(), "configuration not reloaded") {
		t.Errorf("the log does not say why:\n%s", env.log.String())
	}
}

// A reload that changes a setting needing a restart names it in the log.
func TestReloadReportsWhatNeedsARestart(t *testing.T) {
	env := startReloadEnv(t)
	env.write(t, "example.com", "scep:\n  enabled: true\n")
	if err := env.doReload(t); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(env.log.String(), "need a restart") || !strings.Contains(env.log.String(), "scep") {
		t.Errorf("the log does not name the setting that needs a restart:\n%s", env.log.String())
	}
}

// Which changes a reload applies (access rules, ACME domains) and which need
// a restart (listening address, server names, data directory, identity
// provider, ACME or SCEP switched off or on).
func TestNeedsRestart(t *testing.T) {
	base := func() *config.Config {
		return &config.Config{
			DataDir: "/d",
			CA:      config.CA{Name: "N", Organization: "O", KeyType: "ecdsa"},
			Server:  config.Server{Address: ":8443", Names: []string{"localhost"}},
			OIDC:    config.OIDC{Issuer: "https://login.example.com", ClientID: "id", ClientSecret: "s"},
			Access:  []config.AccessRule{{Users: []string{"a"}, Admin: true}},
			ACME:    config.ACME{AllowedDomains: []string{"example.com"}},
		}
	}
	tests := []struct {
		name   string
		change func(*config.Config)
		want   string
	}{
		{"nothing", func(c *config.Config) {}, ""},
		// What a reload is for: no restart.
		{"access rules", func(c *config.Config) {
			c.Access = []config.AccessRule{{Groups: []string{"b"}, SSHPrincipals: []string{"b"}}}
		}, ""},
		{"ACME domains", func(c *config.Config) { c.ACME.AllowedDomains = []string{"other.org"} }, ""},
		// What needs one.
		{"listening address", func(c *config.Config) { c.Server.Address = ":9443" }, "server"},
		{"server names", func(c *config.Config) { c.Server.Names = []string{"ca.example.com"} }, "server"},
		{"data directory", func(c *config.Config) { c.DataDir = "/other" }, "data_dir"},
		{"identity provider", func(c *config.Config) { c.OIDC.ClientSecret = "new" }, "oidc"},
		{"ACME switched off", func(c *config.Config) { c.ACME.AllowedDomains = nil }, "acme"},
		{"SCEP switched on", func(c *config.Config) { c.SCEP.Enabled = true }, "scep"},
	}
	for _, tt := range tests {
		next := base()
		tt.change(next)
		got := strings.Join(needsRestart(base(), next), ",")
		if (tt.want == "") != (got == "") || !strings.Contains(got, tt.want) {
			t.Errorf("%s: needs restart = %q, want %q", tt.name, got, tt.want)
		}
	}
}
