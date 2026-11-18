// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// A backup taken while the server runs is a working CA: restored, it
// knows the certificates issued before.
func TestBackupAndRestore(t *testing.T) {
	first := startTestCA(t)
	leaf, _ := first.issueTLS(t, "web.example.com")

	backup := filepath.Join(t.TempDir(), "backup")
	if err := runBackup(context.Background(), io.Discard, first.cfg, backup); err != nil {
		t.Fatal(err)
	}
	if err := runBackup(context.Background(), io.Discard, first.cfg, backup); err == nil {
		t.Error("an existing backup was overwritten")
	}
	for _, file := range []string{ca.RootCertFile, ca.IntermediateKeyFile, ca.SSHUserCAKeyFile, store.FileName} {
		info, err := os.Stat(filepath.Join(backup, file))
		if err != nil {
			t.Fatalf("%s missing: %v", file, err)
		}
		if file != ca.RootCertFile && info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is readable by others: %v", file, info.Mode())
		}
	}

	// Restore: a CA on the backup.
	restored := *first.cfg
	restored.DataDir = backup
	url := serveForTest(t, &restored)
	second := &testCA{cfg: &restored, url: url, root: filepath.Join(backup, ca.RootCertFile)}
	db, err := store.Open(filepath.Join(backup, store.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Certificate(context.Background(), store.KindX509, store.X509Serial(leaf.SerialNumber)); err != nil {
		t.Errorf("the restored database does not know the certificate: %v", err)
	}
	if _, err := os.Stat(second.root); err != nil {
		t.Fatal(err)
	}
	second.issueTLS(t, "after-restore.example.com")
}
