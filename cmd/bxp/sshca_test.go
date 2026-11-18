// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/server"
)

// The whole replacement of the SSH host CA key, seen by a host: the new
// key is published first, then signs; the host renews its old certificate
// and gets one signed with the new key.
func TestNewSSHHostCA(t *testing.T) {
	testCA := startTestCA(t, withPublicHTTP)
	keyFile, pubFile := writeHostKey(t, t.TempDir())
	conn := testCA.connection(t, "ssh-host", "web1.example.com")
	if err := runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: pubFile}); err != nil {
		t.Fatal(err)
	}
	certFile := keyFile + "-cert.pub"
	old := readSSHCert(t, certFile)

	// Step 1, then a restart: both keys published.
	var out bytes.Buffer
	if err := runNewSSHCA(&out, io.Discard, testCA.cfg, "host", false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "--activate") {
		t.Errorf("output:\n%s", out.String())
	}
	restarted := restart(t, testCA)
	if lines := publishedLines(t, restarted); lines != 2 {
		t.Errorf("/ssh_host_ca.pub has %d keys, want 2 during the replacement", lines)
	}

	// Step 2, then a restart: one key, and the host renews over to it.
	if err := runNewSSHCA(io.Discard, io.Discard, testCA.cfg, "host", true); err != nil {
		t.Fatal(err)
	}
	final := restart(t, testCA)
	if lines := publishedLines(t, final); lines != 1 {
		t.Errorf("/ssh_host_ca.pub has %d keys after the replacement, want 1", lines)
	}
	if err := runRenew(context.Background(), io.Discard, io.Discard, final.renewConn(), renewOptions{cert: certFile, key: keyFile, force: true}); err != nil {
		t.Fatalf("renewing a certificate of the old key: %v", err)
	}
	renewed := readSSHCert(t, certFile)
	if bytes.Equal(renewed.SignatureKey.Marshal(), old.SignatureKey.Marshal()) {
		t.Error("the renewed certificate is signed with the old key")
	}
}

// restart serves the same CA again, as after "systemctl restart bastionxp-ca".
func restart(t *testing.T, c *testCA) *testCA {
	t.Helper()
	cfg := *c.cfg
	url := serveForTest(t, &cfg)
	return &testCA{cfg: &cfg, url: url, root: c.root}
}

func publishedLines(t *testing.T, c *testCA) int {
	t.Helper()
	body := httpGet(t, c.cfg.Server.PublicURL+server.SSHHostCAPath)
	return strings.Count(strings.TrimSpace(string(body)), "\n") + 1
}
