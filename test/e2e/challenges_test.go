// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && !windows

package e2e

import (
	"fmt"
	"net"
	"path/filepath"
	"testing"
)

// needPort makes sure a client can listen on a low port; see needPort80.
func needPort(t *testing.T, port int) {
	t.Helper()
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		missing(t, "cannot listen on port %d (%v); on Linux: sudo sysctl -w net.ipv4.ip_unprivileged_port_start=80", port, err)
	}
	l.Close()
}

// The other ways to prove a name, with real clients: tls-alpn-01 on port
// 443, an IP address (RFC 8738), and a wildcard with dns-01, its TXT record
// written by lego's exec hook into a DNS server the CA asks.
func TestACMEOtherChallenges(t *testing.T) {
	needPort(t, 80)
	needPort(t, 443)
	lego := tool(t, "lego")
	dns := startFakeDNS(t)
	c := newCA(t, fmt.Sprintf(`acme:
  allowed_domains: [e2e.localhost]
  allowed_ip_ranges: [127.0.0.1/32]
  dns_resolver: %s
`, dns.addr))
	c.start()
	directory := c.url + "/acme/directory"
	legoRun := func(t *testing.T, dir string, env []string, args ...string) {
		t.Helper()
		common := []string{"--accept-tos", "--email", "e2e@example.com", "--server", directory, "--path", dir}
		mustRun(t, dir, append([]string{"LEGO_CA_CERTIFICATES=" + c.root}, env...), lego, append(append(common, args...), "run")...)
	}

	t.Run("tls-alpn-01, bxp", func(t *testing.T) {
		c := c.in(t)
		const name = "alpn1.e2e.localhost"
		out := t.TempDir()
		c.client("acme", "issue", "--ca-url", c.url, "--root", c.root, "--challenge", "tls-alpn-01",
			"--tls-address", ":443", "--name", name, "--out-dir", out)
		c.verifyWithOpenSSL(filepath.Join(out, name+".crt"), name)
	})

	t.Run("tls-alpn-01, lego", func(t *testing.T) {
		c := c.in(t)
		const name = "alpn2.e2e.localhost"
		dir := t.TempDir()
		legoRun(t, dir, nil, "--tls", "--tls.port", ":443", "--domains", name)
		c.verifyWithOpenSSL(filepath.Join(dir, "certificates", name+".crt"), name)
	})

	t.Run("IP address, lego", func(t *testing.T) {
		c := c.in(t)
		dir := t.TempDir()
		legoRun(t, dir, nil, "--http", "--http.port", ":80", "--domains", "127.0.0.1")
		certFile := filepath.Join(dir, "certificates", "127.0.0.1.crt")
		cert := c.verifyWithOpenSSL(certFile, "")
		if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) || len(cert.DNSNames) != 0 {
			t.Errorf("names: DNS %v, IP %v; want only 127.0.0.1", cert.DNSNames, cert.IPAddresses)
		}
	})

	t.Run("IP address outside the allowed range", func(t *testing.T) {
		c := c.in(t)
		if r := c.bxp("acme", "issue", "--ca-url", c.url, "--root", c.root, "--name", "10.9.9.9", "--out-dir", t.TempDir()); r.code == 0 {
			t.Errorf("an IP address outside acme.allowed_ip_ranges was issued:\n%s", r)
		}
	})

	t.Run("wildcard, dns-01, lego", func(t *testing.T) {
		c := c.in(t)
		dir := t.TempDir()
		hook := filepath.Join(dir, "dns-hook.sh")
		// lego runs: hook present|cleanup <fqdn> <value>
		writeFile(t, hook, "#!/bin/sh\n[ \"$1\" = present ] && echo \"$2 $3\" >> '"+dns.records+"'\nexit 0\n")
		if err := osChmod(hook, 0o755); err != nil {
			t.Fatal(err)
		}
		legoRun(t, dir, []string{"EXEC_PATH=" + hook},
			"--dns", "exec", "--dns.propagation-wait", "1s", "--dns.resolvers", dns.addr,
			"--domains", "*.wild.e2e.localhost")
		cert := c.verifyWithOpenSSL(filepath.Join(dir, "certificates", "_.wild.e2e.localhost.crt"), "anything.wild.e2e.localhost")
		if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "*.wild.e2e.localhost" {
			t.Errorf("names %v, want *.wild.e2e.localhost", cert.DNSNames)
		}
	})
}
