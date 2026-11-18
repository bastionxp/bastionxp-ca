// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && !windows

package e2e

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// noCrash fails the test if a command crashed instead of refusing.
func noCrash(t *testing.T, r result) {
	t.Helper()
	for _, sign := range []string{"panic:", "goroutine ", "runtime error"} {
		if strings.Contains(r.stdout+r.stderr, sign) {
			t.Errorf("the command crashed:\n%s", r)
		}
	}
}

// The ACME limits, with the real server and client: orders per account,
// and accounts per address. A client over a limit gets a clear refusal.
func TestACMERateLimits(t *testing.T) {
	needPort80(t)

	t.Run("orders per account", func(t *testing.T) {
		c := newCA(t, "acme:\n  allowed_domains: [e2e.localhost]\n  limits:\n    orders_per_account_per_hour: 2\n")
		c.start()
		accountKey := filepath.Join(t.TempDir(), "account.key")
		issue := func(i int) result {
			return c.bxp("acme", "issue", "--ca-url", c.url, "--root", c.root, "--account-key", accountKey,
				"--name", fmt.Sprintf("o%d.e2e.localhost", i), "--out-dir", t.TempDir())
		}
		for i := 1; i <= 2; i++ {
			if r := issue(i); r.code != 0 {
				t.Fatalf("order %d of 2:\n%s", i, r)
			}
		}
		r := issue(3)
		noCrash(t, r)
		if r.code == 0 || !strings.Contains(r.stderr, "too many new orders") {
			t.Errorf("a third order with orders_per_account_per_hour: 2:\n%s", r)
		}
	})

	t.Run("accounts per address", func(t *testing.T) {
		c := newCA(t, "acme:\n  allowed_domains: [e2e.localhost]\n  limits:\n    accounts_per_ip_per_hour: 1\n")
		c.start()
		issue := func(i int) result {
			// A new account key each time: a new account.
			return c.bxp("acme", "issue", "--ca-url", c.url, "--root", c.root,
				"--account-key", filepath.Join(t.TempDir(), "account.key"),
				"--name", fmt.Sprintf("a%d.e2e.localhost", i), "--out-dir", t.TempDir())
		}
		if r := issue(1); r.code != 0 {
			t.Fatalf("the first account:\n%s", r)
		}
		r := issue(2)
		noCrash(t, r)
		if r.code == 0 || !strings.Contains(r.stderr, "too many new accounts") {
			t.Errorf("a second account with accounts_per_ip_per_hour: 1:\n%s", r)
		}
	})
}

// One-time tokens give exactly what they name, for as long as they say,
// and a refused request does not use a token up.
func TestTokenLimits(t *testing.T) {
	sshKeygen := tool(t, "ssh-keygen")
	c := newCA(t, "")
	c.start()
	c.trust()
	refused := func(what string, r result, why string) {
		t.Helper()
		noCrash(t, r)
		if r.code == 0 {
			t.Errorf("%s was accepted:\n%s", what, r)
		} else if !strings.Contains(strings.ToLower(r.stderr), why) {
			t.Errorf("%s: refused, but the message does not say why (%q):\n%s", what, why, r)
		}
	}

	// Expired.
	expiring := strings.TrimSpace(c.admin("token", "--profile", "tls-server", "--name", "late.e2e.localhost", "--valid-for", "1s").stdout)
	time.Sleep(2500 * time.Millisecond)
	refused("an expired token", c.bxp("tls", "--token", expiring, "--name", "late.e2e.localhost", "--out-dir", t.TempDir()), "expired")

	// Names the token does not give; then the token still works for its own.
	tok := c.token("tls-server", "web.e2e.localhost")
	refused("another name", c.bxp("tls", "--token", tok, "--name", "evil.e2e.localhost", "--out-dir", t.TempDir()), "evil.e2e.localhost")
	refused("an extra name", c.bxp("tls", "--token", tok, "--name", "web.e2e.localhost", "--name", "evil.e2e.localhost", "--out-dir", t.TempDir()), "evil.e2e.localhost")
	if r := c.bxp("tls", "--token", tok, "--name", "web.e2e.localhost", "--out-dir", t.TempDir()); r.code != 0 {
		t.Errorf("after refused requests, the token no longer works for its own name:\n%s", r)
	}

	// SSH: a principal the token does not give; a TLS token for SSH.
	key := filepath.Join(t.TempDir(), "id_ed25519")
	mustRun(t, filepath.Dir(key), nil, sshKeygen, "-q", "-t", "ed25519", "-N", "", "-f", key)
	sshToken := c.token("ssh-user", "deploy")
	refused("principal root", c.bxp("ssh", "--token", sshToken, "--key", key+".pub", "--principal", "root"), "root")
	refused("a TLS token for SSH", c.bxp("ssh", "--token", c.token("tls-server", "web2.e2e.localhost"), "--key", key+".pub"), "")
	if r := c.bxp("ssh", "--token", sshToken, "--key", key+".pub"); r.code != 0 {
		t.Errorf("after a refused request, the SSH token no longer works:\n%s", r)
	}
}
