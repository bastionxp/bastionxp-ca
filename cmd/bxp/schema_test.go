// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// setSchema sets the database's schema version, as an older or newer
// BastionXP CA would have left it.
func setSchema(t *testing.T, path string, version int) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, version)); err != nil {
		t.Fatal(err)
	}
}

func schemaOf(t *testing.T, path string) int {
	t.Helper()
	db, err := store.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	v, err := db.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The commands that only look (doctor, list certificates, backup) never
// update the database: a newer version run to look must not change it
// under the server that still runs.
func TestLookingDoesNotUpdateTheDatabase(t *testing.T) {
	testCA := startTestCA(t)
	testCA.issueTLS(t, "web.example.com") // the server is up, and its database exists
	ctx := context.Background()
	path := filepath.Join(testCA.cfg.DataDir, store.FileName)
	current := store.SchemaVersion()

	_, out := doctor(t, testCA.cfg)
	wantLine(t, out, "ok", fmt.Sprintf("the database is intact (schema %d,", current))

	// As if this version were newer than the one that wrote the database.
	setSchema(t, path, current-1)
	_, out = doctor(t, testCA.cfg)
	wantLine(t, out, "warn", fmt.Sprintf("schema %d; this version updates it to %d", current-1, current))
	err := runListCertificates(ctx, io.Discard, testCA.cfg, false, "text")
	if err == nil || !strings.Contains(err.Error(), "older version") {
		t.Errorf("list on an older database: error = %v", err)
	}
	backup := filepath.Join(t.TempDir(), "backup")
	if err := runBackup(ctx, io.Discard, testCA.cfg, backup); err != nil {
		t.Fatal(err)
	}
	if v := schemaOf(t, filepath.Join(backup, store.FileName)); v != current-1 {
		t.Errorf("the backup has schema %d, want the database as it was (%d)", v, current-1)
	}
	if v := schemaOf(t, path); v != current-1 {
		t.Errorf("looking updated the database to schema %d", v)
	}

	// As if an older version were run on a database a newer one updated.
	setSchema(t, path, current+1)
	r, out := doctor(t, testCA.cfg)
	wantLine(t, out, "FAIL", fmt.Sprintf("schema %d, from a newer version", current+1))
	if r.fails == 0 {
		t.Error("doctor did not count the newer database as a failure")
	}
	err = runListCertificates(ctx, io.Discard, testCA.cfg, false, "text")
	if err == nil || !strings.Contains(err.Error(), "newer version") {
		t.Errorf("list on a newer database: error = %v", err)
	}
}
