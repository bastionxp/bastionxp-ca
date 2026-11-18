// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// answers returns an ask function that gives the answers in order, and
// records the questions asked.
func answers(asked *[]string, replies ...string) func(string) (string, error) {
	return func(label string) (string, error) {
		*asked = append(*asked, label)
		if len(replies) == 0 {
			return "", errors.New("asked more often than expected")
		}
		r := replies[0]
		replies = replies[1:]
		return r, nil
	}
}

// Asking for a new passphrase: the rule is shown first; a short one is
// refused before it is asked again; two that differ are asked again; after
// three failed tries it gives up.
func TestAskNewPassphrase(t *testing.T) {
	const good = "correct horse battery"
	for _, tc := range []struct {
		name    string
		replies []string
		asked   []string // the questions, in order
		wantErr string
		output  []string // lines expected in what the user sees
	}{
		{
			name:    "first time right",
			replies: []string{good, good},
			asked:   []string{"Passphrase", "Again"},
			output:  []string{"at least 12 characters"},
		},
		{
			// The length is checked before "Again", not after it.
			name:    "too short, then right",
			replies: []string{"short", good, good},
			asked:   []string{"Passphrase", "Passphrase", "Again"},
			output:  []string{"The passphrase must have at least 12 characters (that one had 5). Try again."},
		},
		{
			name:    "typed differently, then right",
			replies: []string{good, good + "x", good, good},
			asked:   []string{"Passphrase", "Again", "Passphrase", "Again"},
			output:  []string{"The two passphrases differ. Try again."},
		},
		{
			name:    "gives up after three tries",
			replies: []string{"a", "b", "c"},
			asked:   []string{"Passphrase", "Passphrase", "Passphrase"},
			wantErr: "at least 12 characters (3 tries)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			var asked []string
			got, err := askNewPassphraseWith(&out, "Passphrase", answers(&asked, tc.replies...))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tc.wantErr)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != good {
					t.Errorf("passphrase = %q, want %q", got, good)
				}
			}
			if strings.Join(asked, ",") != strings.Join(tc.asked, ",") {
				t.Errorf("asked %v, want %v", asked, tc.asked)
			}
			if !strings.HasPrefix(out.String(), "Choose a passphrase of at least 12 characters.") {
				t.Errorf("the rule is not shown first:\n%s", out.String())
			}
			for _, line := range tc.output {
				if !strings.Contains(out.String(), line) {
					t.Errorf("output lacks %q:\n%s", line, out.String())
				}
			}
		})
	}
}

// "bxp init" on a data directory that already holds a CA, or with a root
// key already where it would write one, fails before asking for any
// passphrase. Tests have no terminal, so asking would fail differently.
func TestInitFailsBeforeAsking(t *testing.T) {
	cfg := newTestConfig(t)
	if err := runInit(io.Discard, cfg, testInit); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(t.TempDir(), "bastionxp-ca.yaml")
	content := "data_dir: " + cfg.DataDir + "\nca:\n  organization: Test Org\n"
	if err := os.WriteFile(configFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	existingKey := filepath.Join(t.TempDir(), "root.key")
	if err := os.WriteFile(existingKey, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	emptyConfig := filepath.Join(t.TempDir(), "empty.yaml")
	content = "data_dir: " + t.TempDir() + "\nca:\n  organization: Test Org\n"
	if err := os.WriteFile(emptyConfig, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"already initialized", []string{"init", "--config", configFile}, "already initialized"},
		{"external root, already initialized", []string{"init", "--config", configFile, "--external-root"}, "already initialized"},
		{"root key already there", []string{"init", "--config", emptyConfig, "--root-key-out", existingKey}, "never overwritten"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newRootCommand()
			var out, errOut bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&errOut)
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
			if strings.Contains(errOut.String(), "passphrase") {
				t.Errorf("asked for a passphrase first:\n%s", errOut.String())
			}
		})
	}
}
