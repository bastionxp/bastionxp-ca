// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && !windows

package e2e

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// acmeConfig lets ACME clients get certificates for names below
// e2e.localhost. Names ending in .localhost point to this machine, so the
// CA's http-01 check reaches the client on port 80 here.
const acmeConfig = `acme:
  allowed_domains: [e2e.localhost]
`

// needPort80 makes sure a client can listen on port 80. macOS lets any
// program do that. Linux needs, once:
//
//	sudo sysctl -w net.ipv4.ip_unprivileged_port_start=80
func needPort80(t *testing.T) {
	t.Helper()
	l, err := net.Listen("tcp", ":80")
	if err != nil {
		missing(t, "cannot listen on port 80 for http-01 (%v); on Linux: sudo sysctl -w net.ipv4.ip_unprivileged_port_start=80", err)
	}
	l.Close()
}

// Every ACME client gets a certificate from the real server, proving its
// name with http-01 on port 80. They run one after the other: they all
// need port 80.
func TestACMEClients(t *testing.T) {
	needPort80(t)
	c := newCA(t, acmeConfig)
	c.start()
	directory := c.url + "/acme/directory"

	t.Run("bxp", func(t *testing.T) {
		c := c.in(t)
		const name = "bxp.e2e.localhost"
		out := t.TempDir()
		c.client("acme", "issue", "--ca-url", c.url, "--root", c.root, "--name", name, "--out-dir", out)
		certFile := filepath.Join(out, name+".crt")
		c.verifyWithOpenSSL(certFile, name)

		// The rest of the certificate's life, with the same client.
		c.client("acme", "renew", "--ca-url", c.url, "--root", c.root, "--force",
			"--cert", certFile, "--key", filepath.Join(out, name+".key"))
		c.verifyWithOpenSSL(certFile, name)
		c.client("acme", "revoke", "--ca-url", c.url, "--root", c.root, "--cert", certFile, "--reason", "superseded")
		c.assertRevoked(certFile)

		// Revoked: the CA's renewal information says "now", so a plain
		// renew (no --force) replaces it.
		revoked := readCerts(t, certFile)[0]
		c.client("acme", "renew", "--ca-url", c.url, "--root", c.root,
			"--cert", certFile, "--key", filepath.Join(out, name+".key"))
		if c.verifyWithOpenSSL(certFile, name).SerialNumber.Cmp(revoked.SerialNumber) == 0 {
			t.Error("bxp acme renew did not renew a revoked certificate")
		}
	})

	t.Run("certbot", func(t *testing.T) {
		c := c.in(t)
		certbot := tool(t, "certbot")
		const name = "certbot.e2e.localhost"
		dir := t.TempDir()
		env := []string{"REQUESTS_CA_BUNDLE=" + c.root}
		dirs := []string{"--non-interactive",
			"--config-dir", filepath.Join(dir, "config"),
			"--work-dir", filepath.Join(dir, "work"),
			"--logs-dir", filepath.Join(dir, "logs")}
		live := filepath.Join(dir, "config", "live", name)
		certFile := filepath.Join(live, "fullchain.pem")

		mustRun(t, dir, env, certbot, append([]string{"certonly", "--standalone", "--agree-tos",
			"--register-unsafely-without-email", "--server", directory, "-d", name}, dirs...)...)
		first := c.verifyWithOpenSSL(certFile, name)

		// Without a terminal certbot first sleeps up to 8 minutes, as from cron.
		renew := append([]string{"renew", "--no-random-sleep-on-renew"}, dirs...)

		// ACME Renewal Information (RFC 9773). By its own rule certbot
		// leaves a certificate this young alone; once it is revoked, the
		// CA says "now" and a plain renew replaces it. certbot sends
		// "replaces", which the CA must accept. (certbot then waits for
		// the CA's Retry-After, an hour, before it asks again: so ask only
		// once here.)
		c.admin("revoke", first.SerialNumber.Text(16), "--reason", "superseded")
		mustRun(t, dir, env, certbot, renew...)
		second := c.verifyWithOpenSSL(certFile, name)
		if second.SerialNumber.Cmp(first.SerialNumber) == 0 {
			t.Fatal("certbot did not renew a revoked certificate: the CA's renewal information was not used")
		}
		// The new certificate is fresh: nothing to do.
		mustRun(t, dir, env, certbot, renew...)
		if c.verifyWithOpenSSL(certFile, name).SerialNumber.Cmp(second.SerialNumber) != 0 {
			t.Fatal("certbot renewed a fresh certificate")
		}

		mustRun(t, dir, env, certbot, append(renew, "--force-renewal")...)
		if c.verifyWithOpenSSL(certFile, name).SerialNumber.Cmp(second.SerialNumber) == 0 {
			t.Error("certbot renew --force-renewal did not get a new certificate")
		}

		// Revoked with the certificate's own key, not the account's.
		mustRun(t, dir, env, certbot, append([]string{"revoke", "--server", directory,
			"--cert-path", filepath.Join(live, "cert.pem"), "--key-path", filepath.Join(live, "privkey.pem"),
			"--reason", "keycompromise", "--no-delete-after-revoke"}, dirs...)...)
		c.assertRevoked(certFile)

		mustRun(t, dir, env, certbot, append([]string{"unregister", "--server", directory}, dirs...)...)
	})

	t.Run("lego", func(t *testing.T) {
		c := c.in(t)
		lego := tool(t, "lego")
		const name = "lego.e2e.localhost"
		dir := t.TempDir()
		env := []string{"LEGO_CA_CERTIFICATES=" + c.root}
		common := []string{"--accept-tos", "--email", "e2e@example.com",
			"--server", directory, "--domains", name,
			"--http", "--http.port", ":80", "--path", dir}
		certFile := filepath.Join(dir, "certificates", name+".crt")

		mustRun(t, dir, env, lego, append(common, "run")...)
		first := c.verifyWithOpenSSL(certFile, name)

		// The default --days 30 renews a 24-hour certificate on every run.
		mustRun(t, dir, env, lego, append(common, "renew", "--no-random-sleep")...)
		if c.verifyWithOpenSSL(certFile, name).SerialNumber.Cmp(first.SerialNumber) == 0 {
			t.Error("lego renew did not get a new certificate")
		}

		mustRun(t, dir, env, lego, append(common, "revoke", "--keep")...)
		c.assertRevoked(certFile)
	})

	t.Run("acme.sh", func(t *testing.T) {
		c := c.in(t)
		acmesh := tool(t, "acme.sh")
		tool(t, "socat") // acme.sh --standalone answers http-01 with socat
		const name = "acmesh.e2e.localhost"
		dir := t.TempDir()
		homes := []string{"--home", dir, "--config-home", dir}
		// acme.sh keeps ECDSA certificates (its default) in <name>_ecc.
		certFile := filepath.Join(dir, name+"_ecc", "fullchain.cer")

		mustRun(t, dir, nil, acmesh, append([]string{"--issue", "--standalone", "--httpport", "80",
			"--server", directory, "--ca-bundle", c.root, "-d", name}, homes...)...)
		first := c.verifyWithOpenSSL(certFile, name)

		mustRun(t, dir, nil, acmesh, append([]string{"--renew", "-d", name, "--ecc", "--force"}, homes...)...)
		if c.verifyWithOpenSSL(certFile, name).SerialNumber.Cmp(first.SerialNumber) == 0 {
			t.Error("acme.sh --renew did not get a new certificate")
		}

		mustRun(t, dir, nil, acmesh, append([]string{"--revoke", "-d", name, "--ecc"}, homes...)...)
		c.assertRevoked(certFile)
	})

	// The CA's own view of it all.
	t.Run("list", func(t *testing.T) {
		c := c.in(t)
		orders := c.admin("list", "acme-orders").stdout
		for _, name := range []string{"bxp", "certbot", "lego", "acmesh"} {
			want := name + ".e2e.localhost  valid  http-01"
			if !strings.Contains(orders, want) {
				t.Errorf("bxp list acme-orders lacks %q:\n%s", want, orders)
			}
		}
		if failed := c.admin("list", "acme-orders", "--failed").stdout; !strings.Contains(failed, "No ACME orders.") {
			t.Errorf("failed orders listed:\n%s", failed)
		}
		// lego and acme.sh renew with "replaces" (RFC 9773). certbot reads
		// renewal information but does not send it.
		var list []struct {
			Names    []string `json:"names"`
			Replaces string   `json:"replaces"`
		}
		if err := json.Unmarshal([]byte(c.admin("list", "acme-orders", "--format", "json").stdout), &list); err != nil {
			t.Fatal(err)
		}
		replaced := map[string]bool{}
		for _, o := range list {
			if o.Replaces != "" {
				replaced[o.Names[0]] = true
			}
		}
		for _, name := range []string{"lego.e2e.localhost", "acmesh.e2e.localhost"} {
			if !replaced[name] {
				t.Errorf("no order for %s says which certificate it replaces: %v", name, replaced)
			}
		}

		var accounts []map[string]any
		if err := json.Unmarshal([]byte(c.admin("list", "acme-accounts", "--format", "json").stdout), &accounts); err != nil {
			t.Fatal(err)
		}
		// One account per client.
		if len(accounts) != 4 {
			t.Errorf("%d ACME accounts, want 4: %v", len(accounts), accounts)
		}
	})
}
