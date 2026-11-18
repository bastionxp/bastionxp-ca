// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && !windows

package e2e

import (
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"testing"
)

const scepConfig = `scep:
  enabled: true
`

// Devices enroll over SCEP with a one-time token as the challenge, with
// bxp's own client and with micromdm's scepclient.
func TestSCEPClients(t *testing.T) {
	c := newCA(t, scepConfig)
	c.start()

	t.Run("bxp", func(t *testing.T) {
		c := c.in(t)
		const name = "device1.e2e.localhost"
		out := t.TempDir()
		c.client("scep", "enroll", "--ca-url", c.url, "--root", c.root,
			"--token", c.token("tls-device", name), "--name", name, "--out-dir", out)
		certFile := filepath.Join(out, name+".crt")
		c.verifyWithOpenSSLFor("sslclient", certFile, name)

		// Renewal needs no token: the device signs with its current
		// certificate (RFC 8894).
		c.client("scep", "renew", "--ca-url", c.url, "--root", c.root,
			"--cert", certFile, "--key", filepath.Join(out, name+".key"))
		c.verifyWithOpenSSLFor("sslclient", certFile, name)
	})

	t.Run("scepclient", func(t *testing.T) {
		c := c.in(t)
		scepclient := tool(t, "scepclient")
		const name = "device2.e2e.localhost"
		dir := t.TempDir()
		pemFile := filepath.Join(dir, "device.pem")
		mustRun(t, dir, nil, scepclient,
			"-server-url", scepProxy(t, c)+"/scep",
			"-challenge", c.token("tls-device", name),
			"-cn", name, "-dnsname", name,
			"-private-key", filepath.Join(dir, "device.key"),
			"-certificate", pemFile,
			"-key-encipherment-selector")
		c.verifyWithOpenSSLFor("sslclient", pemFile, name)
	})
}

// scepProxy returns the address of a plain HTTP proxy to the CA, for
// scepclient. It cannot be told which root to trust, and on macOS Go
// programs ignore SSL_CERT_FILE. The proxy handles only TLS: everything
// SCEP itself does (signing, encryption, the challenge) is unchanged.
func scepProxy(t *testing.T, c *testCA) string {
	t.Helper()
	target, err := url.Parse(c.url)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = c.httpsClient().Transport
	front := httptest.NewServer(proxy)
	t.Cleanup(front.Close)
	return front.URL
}
