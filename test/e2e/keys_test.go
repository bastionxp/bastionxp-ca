// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && !windows

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const serverKeyPassphrase = "e2e server key passphrase"

// The server's keys encrypted (init with a configured passphrase): the
// server starts with the passphrase from each place it looks, and stops
// with a clear error, at once, without it or with a wrong one. There is no
// terminal to ask on.
func TestEncryptedServerKeys(t *testing.T) {
	secrets := t.TempDir() // outside data_dir, as the server demands
	passphraseFile := filepath.Join(secrets, "key-passphrase")
	writeFile(t, passphraseFile, serverKeyPassphrase+"\n")
	c := newCAWith(t, caOptions{caYAML: "key_passphrase_file: " + passphraseFile})

	// The keys are really encrypted.
	for _, key := range []string{"intermediate.key", "ssh_user_ca.key", "ssh_host_ca.key", "token.key"} {
		if !strings.Contains(string(readFile(t, filepath.Join(c.dataDir, key))), "ENCRYPTED PRIVATE KEY") {
			t.Errorf("%s is not encrypted", key)
		}
	}

	t.Run("ca.key_passphrase_file", func(t *testing.T) {
		c := c.in(t)
		c.start()
		c.waitForLog("are encrypted")
		c.waitForLog("passphrase_from=ca.key_passphrase_file")
		c.trust()
		const name = "enc.e2e.localhost"
		out := t.TempDir()
		c.client("tls", "--token", c.token("tls-server", name), "--name", name, "--out-dir", out)
		c.verifyWithOpenSSL(filepath.Join(out, name+".crt"), name)
		if err := c.stop(); err != nil {
			t.Fatal(err)
		}
	})

	// From here on the configuration names no file: the other places.
	config := strings.Replace(string(readFile(t, c.config)), "  key_passphrase_file: "+passphraseFile+"\n", "", 1)
	writeFile(t, c.config, config)

	credentials := t.TempDir()
	writeFile(t, filepath.Join(credentials, "bastionxp-ca-key-passphrase"), serverKeyPassphrase)
	for _, tc := range []struct {
		name string
		env  string
		from string
	}{
		{"systemd credential", "CREDENTIALS_DIRECTORY=" + credentials, "passphrase_from=\"systemd credential bastionxp-ca-key-passphrase\""},
		{"BXP_KEY_PASSPHRASE_FILE", "BXP_KEY_PASSPHRASE_FILE=" + passphraseFile, "passphrase_from=BXP_KEY_PASSPHRASE_FILE"},
		{"BXP_KEY_PASSPHRASE", "BXP_KEY_PASSPHRASE=" + serverKeyPassphrase, "passphrase_from=BXP_KEY_PASSPHRASE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := c.in(t)
			c.logs = &syncBuffer{}
			c.serveEnv = []string{tc.env}
			c.start()
			c.waitForLog(tc.from)
			if strings.Contains(c.logs.String(), serverKeyPassphrase) {
				t.Errorf("the passphrase is in the server's log:\n%s", c.logs)
			}
			if err := c.stop(); err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("wrong passphrase", func(t *testing.T) {
		c := c.in(t)
		r := c.serveFails("BXP_KEY_PASSPHRASE=not the passphrase")
		// It says where the wrong passphrase came from.
		if r.code == 0 || !strings.Contains(r.stderr, "the passphrase from BXP_KEY_PASSPHRASE does not open the server's keys") {
			t.Errorf("serve with a wrong passphrase:\n%s", r)
		}
		if strings.Contains(r.stdout+r.stderr, "not the passphrase") {
			t.Errorf("the wrong passphrase is printed:\n%s", r)
		}
	})

	t.Run("no passphrase, no terminal", func(t *testing.T) {
		c := c.in(t)
		// Make sure nothing from the test's own environment helps.
		for _, v := range []string{"BXP_KEY_PASSPHRASE", "BXP_KEY_PASSPHRASE_FILE", "CREDENTIALS_DIRECTORY"} {
			if _, ok := os.LookupEnv(v); ok {
				t.Skipf("%s is set in the test's environment", v)
			}
		}
		r := c.serveFails()
		if r.code == 0 || !strings.Contains(r.stderr, "the server's keys are encrypted") {
			t.Errorf("serve without a passphrase:\n%s", r)
		}
	})
}
