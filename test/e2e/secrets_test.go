// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && !windows

package e2e

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// Nothing secret reaches the server's log or what the client commands
// print, even at the debug level: not the one-time tokens (they are
// passwords until used), not the passphrases, not a private key. And with
// --log-format json, every line is JSON, for log collectors.
func TestNoSecretsInLogs(t *testing.T) {
	sshKeygen := tool(t, "ssh-keygen")
	c := newCAWith(t, caOptions{
		extraYAML: scepConfig,
		initEnv:   []string{"BXP_KEY_PASSPHRASE=" + serverKeyPassphrase},
	})
	c.serveEnv = []string{"BXP_KEY_PASSPHRASE=" + serverKeyPassphrase}
	// "bxp token" and "bxp revoke" on the CA machine open the keys too.
	c.env = append(c.env, "BXP_KEY_PASSPHRASE="+serverKeyPassphrase)
	c.serveArgs = []string{"--log-format", "json", "--log-level", "debug"}
	c.start()
	c.trust()

	var tokens []string // every token used, to look for later
	var printed strings.Builder
	record := func(r result) { printed.WriteString(r.stdout + r.stderr) }
	newToken := func(profile string, names ...string) string {
		tok := c.token(profile, names...)
		tokens = append(tokens, tok)
		return tok
	}
	out := t.TempDir()

	// TLS with a token, the token again (refused), then renewal and
	// revocation.
	const name = "secret.e2e.localhost"
	tok := newToken("tls-server", name)
	record(c.client("tls", "--token", tok, "--name", name, "--out-dir", out))
	if r := c.bxp("tls", "--token", tok, "--name", name, "--out-dir", t.TempDir()); r.code == 0 {
		t.Error("a token was used twice")
	} else {
		record(r)
	}
	certFile, keyFile := filepath.Join(out, name+".crt"), filepath.Join(out, name+".key")
	record(c.client("renew", "--cert", certFile, "--key", keyFile, "--force"))
	record(c.admin("revoke", readCerts(t, certFile)[0].SerialNumber.Text(16)))

	// A forged token: a real one with its signature changed.
	forged := newToken("tls-server", "forged.e2e.localhost")
	forged = forged[:len(forged)-4] + "AAAA"
	tokens = append(tokens, forged)
	if r := c.bxp("tls", "--token", forged, "--name", "forged.e2e.localhost", "--out-dir", t.TempDir()); r.code == 0 {
		t.Error("a forged token was accepted")
	} else {
		record(r)
	}

	// SSH with a token, and SCEP with a token as the challenge password.
	sshKey := filepath.Join(out, "id_ed25519")
	mustRun(t, out, nil, sshKeygen, "-q", "-t", "ed25519", "-N", "", "-f", sshKey)
	record(c.client("ssh", "--token", newToken("ssh-user", "deploy"), "--key", sshKey+".pub"))
	const device = "device.e2e.localhost"
	record(c.client("scep", "enroll", "--token", newToken("tls-device", device), "--name", device, "--out-dir", t.TempDir()))

	// Let the server log the revocation it notices, then stop it, so that
	// the log is complete.
	c.waitForLog("certificate revoked")
	if err := c.stop(); err != nil {
		t.Fatal(err)
	}
	logs := c.logs.String()

	// Every line is JSON.
	lines := 0
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Errorf("not a JSON log line: %q", line)
			continue
		}
		lines++
	}
	if lines < 10 {
		t.Errorf("only %d log lines: is the log level applied?", lines)
	}

	// The token events are there, by the token's ID, which is not secret:
	// so the checks below look at a log that saw the tokens.
	for _, event := range []string{`"msg":"certificate issued"`, `"token_id":`, `"msg":"token used twice"`} {
		if !strings.Contains(logs, event) {
			t.Errorf("the log lacks %s: the test would not see a leak", event)
		}
	}

	// Nothing secret, in the log or in what the clients printed.
	secrets := map[string]string{
		"the root key's passphrase":    rootPassphrase,
		"the server keys' passphrase":  serverKeyPassphrase,
		"a private key":                "PRIVATE KEY",
		"a private key (OpenSSH form)": "OPENSSH PRIVATE KEY",
	}
	for i, tok := range tokens {
		secrets["token "+string(rune('A'+i))] = tok
		// A JWT's last part is its signature: logging it alone would do
		// the same harm.
		if parts := strings.Split(tok, "."); len(parts) == 3 && len(parts[2]) > 16 {
			secrets["the signature of token "+string(rune('A'+i))] = parts[2]
		}
	}
	for what, secret := range secrets {
		if strings.Contains(logs, secret) {
			t.Errorf("the server's log holds %s", what)
		}
		if strings.Contains(printed.String(), secret) {
			t.Errorf("a client command printed %s", what)
		}
	}
	if t.Failed() {
		t.Logf("client output:\n%s", printed.String())
	}
}
