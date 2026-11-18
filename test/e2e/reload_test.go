// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && !windows

package e2e

import (
	"path/filepath"
	"strings"
	"testing"
)

// A reload (SIGHUP) applies what it says it applies, at once: an ACME
// domain allowed by the new configuration works without a restart. A
// change that needs a restart is reported, and the server goes on as it
// was.
func TestReloadApplies(t *testing.T) {
	needPort80(t)
	c := newCA(t, "acme:\n  allowed_domains: [first.e2e.localhost]\n")
	c.start()
	issue := func(name string) result {
		t.Helper()
		return c.bxp("acme", "issue", "--ca-url", c.url, "--root", c.root, "--name", name, "--out-dir", t.TempDir())
	}

	if r := issue("second.e2e.localhost"); r.code == 0 {
		t.Fatalf("a domain the configuration does not allow was issued:\n%s", r)
	}

	// Allow it, and reload.
	config := string(readFile(t, c.config))
	config = strings.Replace(config, "allowed_domains: [first.e2e.localhost]",
		"allowed_domains: [first.e2e.localhost, second.e2e.localhost]", 1)
	writeFile(t, c.config, config)
	if err := c.server.Process.Signal(syscallHangup); err != nil {
		t.Fatal(err)
	}
	c.waitForLog("configuration reloaded")

	out := t.TempDir()
	if r := c.bxp("acme", "issue", "--ca-url", c.url, "--root", c.root, "--name", "second.e2e.localhost", "--out-dir", out); r.code != 0 {
		t.Fatalf("after the reload, the newly allowed domain is still refused:\n%s", r)
	}
	c.verifyWithOpenSSL(filepath.Join(out, "second.e2e.localhost.crt"), "second.e2e.localhost")

	// A setting that needs a restart: reported, not applied, and the
	// server goes on serving.
	config = strings.Replace(string(readFile(t, c.config)), "names: [localhost, 127.0.0.1]", "names: [localhost, 127.0.0.1, ca.e2e.localhost]", 1)
	writeFile(t, c.config, config)
	if err := c.server.Process.Signal(syscallHangup); err != nil {
		t.Fatal(err)
	}
	c.waitForLog("these changes need a restart")
	if !c.running() {
		t.Fatal("the server stopped")
	}
	if r := issue("first.e2e.localhost"); r.code != 0 {
		t.Errorf("the server does not issue after a reload with a restart-only change:\n%s", r)
	}
}
