// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// A backup is a complete copy at the current schema, with the data of the
// original, and never overwrites an existing file.
func TestBackupTo(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.UseToken(ctx, "token-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	backup := filepath.Join(t.TempDir(), "copy.db")
	if err := db.BackupTo(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if err := db.BackupTo(ctx, backup); err == nil {
		t.Error("an existing file was overwritten")
	}

	if v := userVersion(t, backup); v != SchemaVersion() {
		t.Errorf("the copy has schema %d, want %d", v, SchemaVersion())
	}
	// The copy has what the original had.
	restored, err := Open(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err := restored.UseToken(ctx, "token-1", time.Now().Add(time.Hour)); err != ErrTokenUsed {
		t.Errorf("token in the copy: %v, want ErrTokenUsed", err)
	}
}
