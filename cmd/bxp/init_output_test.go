// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// wantEveryFileNamed checks that the output names every file in dir. An
// administrator decides permissions and backups from this list, so a file
// that init makes but does not name would be a file nobody knows about.
func wantEveryFileNamed(t *testing.T, output, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Type().IsRegular() && !strings.Contains(output, filepath.Join(dir, e.Name())) {
			t.Errorf("init made %s but does not name it:\n%s", e.Name(), output)
		}
	}
}

// bxp init lists every file it wrote: what to hand out, what to move
// offline, and what the server needs, with the root key's own place when it
// is elsewhere.
func TestInitNamesEveryFile(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		cfg := newTestConfig(t)
		opts := testInit
		heading := "secret, not encrypted"
		if encrypted {
			opts.keyPassphrase = []byte(testKeyPassphrase)
			heading = "secret, encrypted"
		}
		var out bytes.Buffer
		if err := runInit(&out, cfg, opts); err != nil {
			t.Fatal(err)
		}
		wantEveryFileNamed(t, out.String(), cfg.DataDir)
		for _, want := range []string{"To hand out (public):", "To move offline:", heading} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("encrypted=%v: output lacks %q:\n%s", encrypted, want, out.String())
			}
		}
	}

	// The root key elsewhere: named where it is.
	cfg := newTestConfig(t)
	opts := testInit
	opts.rootKeyOut = filepath.Join(t.TempDir(), "root.key")
	var out bytes.Buffer
	if err := runInit(&out, cfg, opts); err != nil {
		t.Fatal(err)
	}
	wantEveryFileNamed(t, out.String(), cfg.DataDir)
	if !strings.Contains(out.String(), "Offline (never in data_dir):") || !strings.Contains(out.String(), opts.rootKeyOut) {
		t.Errorf("the offline root key is not named:\n%s", out.String())
	}
}

// bxp init under another root lists every file, the CSR once.
func TestInitExternalNamesEveryFile(t *testing.T) {
	cfg := newTestConfig(t)
	var out bytes.Buffer
	if err := runInitExternal(&out, cfg, nil); err != nil {
		t.Fatal(err)
	}
	wantEveryFileNamed(t, out.String(), cfg.DataDir)
	// The CSR's path is named once, in the list.
	csr := filepath.Join(cfg.DataDir, "intermediate.next.csr")
	if n := strings.Count(out.String(), csr); n != 1 {
		t.Errorf("the CSR's path appears %d times, want once:\n%s", n, out.String())
	}
}
