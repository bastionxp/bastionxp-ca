// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func userVersion(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func setUserVersion(t *testing.T, path string, v int, extra string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if extra != "" {
		if _, err := db.Exec(extra); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v)); err != nil {
		t.Fatal(err)
	}
}

// A new database gets the current schema version, and opening it again
// changes nothing.
func TestNewDatabaseGetsTheSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if v := userVersion(t, path); v != SchemaVersion() {
		t.Errorf("user_version = %d, want %d", v, SchemaVersion())
	}
	// Opening again changes nothing.
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
}

// An older version must not touch a database a newer one wrote.
func TestNewerDatabaseIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	setUserVersion(t, path, SchemaVersion()+1, "")
	_, err := Open(path)
	if !errors.Is(err, ErrNewerDatabase) {
		t.Errorf("error = %v, want ErrNewerDatabase", err)
	}
}

// A database at an older schema gets the migrations it has not had, once,
// and keeps its data. (Shown with a made-up migration: the first release
// has only the first schema.)
func TestMigrationsRunOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UseToken(context.Background(), "kept", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	db.Close()

	saved := migrations
	t.Cleanup(func() { migrations = saved })
	migrations = append(slices.Clone(saved), `CREATE TABLE later (x INTEGER);`)

	for range 2 { // the second Open must not run it again
		db, err = Open(path)
		if err != nil {
			t.Fatal(err)
		}
		db.Close()
	}
	if v := userVersion(t, path); v != len(saved)+1 {
		t.Errorf("user_version = %d, want %d", v, len(saved)+1)
	}
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.UseToken(context.Background(), "kept", time.Now().Add(time.Hour)); err != ErrTokenUsed {
		t.Errorf("the data before the migration is gone: %v", err)
	}
}

// A read-only open leaves the database as it is: an older one is not
// updated, nothing can be written, a missing one is not created, and a
// consistent copy can still be made.
func TestOpenReadOnly(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)

	if _, err := OpenReadOnly(path); err == nil {
		t.Fatal("a missing database was opened")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("OpenReadOnly created the database")
	}

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ro.CheckVersion(ctx); err != nil {
		t.Errorf("current schema: %v", err)
	}
	if err := ro.UseToken(ctx, "x", time.Now().Add(time.Hour)); err == nil {
		t.Error("a write through a read-only store worked")
	}
	backup := filepath.Join(dir, "copy.db")
	if err := ro.BackupTo(ctx, backup); err != nil {
		t.Errorf("backup through a read-only store: %v", err)
	}
	ro.Close()

	// An older database: reported, not updated.
	setUserVersion(t, path, SchemaVersion()-1, "")
	ro, err = OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ro.CheckVersion(ctx); !errors.Is(err, ErrOlderDatabase) {
		t.Errorf("older schema: error = %v, want ErrOlderDatabase", err)
	}
	ro.Close()
	if v := userVersion(t, path); v != SchemaVersion()-1 {
		t.Errorf("the read-only open changed the schema version to %d", v)
	}

	// A newer one.
	setUserVersion(t, path, SchemaVersion()+1, "")
	ro, err = OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if err := ro.CheckVersion(ctx); !errors.Is(err, ErrNewerDatabase) {
		t.Errorf("newer schema: error = %v, want ErrNewerDatabase", err)
	}
}
