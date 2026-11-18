// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package store is the CA's database: one SQLite file in the data directory.
//
// It remembers which one-time tokens were already used (this file), what
// the ACME server needs (acme.go), and every certificate the CA has
// issued and whether it was revoked (certificates.go).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" database driver
)

// FileName is the name of the database file inside the data directory.
const FileName = "bastionxp-ca.db"

// ErrTokenUsed is returned by UseToken when the token was used before.
var ErrTokenUsed = errors.New("token was already used")

// The database carries a schema version (SQLite's user_version), so that
// a newer version can bring an older database up to date when it starts.
//
// migrations[i] takes the database from version i to version i+1. Each
// runs once, in a transaction with the version change. To change the
// schema: add a migration at the end. Never edit one that was released.
var migrations = []string{
	// 0 -> 1: the first schema, of the first release.
	schema + acmeSchema + certificatesSchema,
}

// SchemaVersion is the version of the database this version writes.
func SchemaVersion() int { return len(migrations) }

// ErrNewerDatabase is returned by Open for a database written by a newer
// BastionXP CA.
var ErrNewerDatabase = errors.New("the database is from a newer version of BastionXP CA")

// schema creates the tables of used tokens.
const schema = `
CREATE TABLE IF NOT EXISTS used_tokens (
	id         TEXT    PRIMARY KEY,
	expires_at INTEGER NOT NULL  -- Unix seconds
);
`

// Store is an open database. Create one with Open and Close it at the end.
// It is safe for concurrent use.
type Store struct {
	db *sql.DB
}

// Open opens the database file at path and creates it if it does not exist.
func Open(path string) (*Store, error) {
	// busy_timeout: if another process holds the database lock, wait up
	// to five seconds instead of failing right away.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// SQLite allows one writer at a time. One connection keeps things
	// simple and is plenty for a CA.
	db.SetMaxOpenConns(1)

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

// OpenReadOnly opens an existing database as it is: its schema is never
// updated, and nothing can be written. For the commands that only look
// (doctor, list, backup), so that running a newer version to look does not
// update the database under an older server that still runs.
//
// The schema may not be this version's: call CheckVersion before reading
// with the other methods.
func OpenReadOnly(path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

// Version returns the database's schema version.
func (s *Store) Version(ctx context.Context) (int, error) {
	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return 0, fmt.Errorf("read the schema version: %w", err)
	}
	return version, nil
}

// ErrOlderDatabase is returned by CheckVersion for a database that this
// BastionXP CA has not updated yet. "bxp serve" updates it when it starts.
var ErrOlderDatabase = errors.New("the database is from an older version of BastionXP CA")

// CheckVersion returns nil if the database has the schema this version
// uses, ErrOlderDatabase or ErrNewerDatabase otherwise.
func (s *Store) CheckVersion(ctx context.Context) error {
	version, err := s.Version(ctx)
	if err != nil {
		return err
	}
	switch {
	case version > SchemaVersion():
		return fmt.Errorf("%w (schema %d; this version knows up to %d): use the newer version, or restore the backup from before the upgrade",
			ErrNewerDatabase, version, SchemaVersion())
	case version < SchemaVersion():
		return fmt.Errorf("%w (schema %d; this version uses %d): \"bxp serve\" updates it when it starts",
			ErrOlderDatabase, version, SchemaVersion())
	}
	return nil
}

// migrate brings the database to SchemaVersion.
func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("%w (schema %d; this version knows up to %d): upgrade BastionXP CA", ErrNewerDatabase, version, len(migrations))
	}
	for ; version < len(migrations); version++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[version]); err != nil {
			tx.Rollback()
			return fmt.Errorf("update the database to schema %d: %w", version+1, err)
		}
		// PRAGMA takes no parameters; version is a number we made.
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, version+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// UseToken records that the token with this ID was used. It returns
// ErrTokenUsed if it was recorded before. The check and the record are one
// database statement, so of two requests with the same token only one wins.
//
// expires is when the token itself expires. After that the record is no
// longer needed, because an expired token is rejected anyway.
func (s *Store) UseToken(ctx context.Context, id string, expires time.Time) error {
	if id == "" {
		return errors.New("token ID is empty")
	}

	// Tidy up records of tokens that have expired.
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM used_tokens WHERE expires_at < ?`, time.Now().Unix()); err != nil {
		return fmt.Errorf("remove expired tokens: %w", err)
	}

	result, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO used_tokens (id, expires_at) VALUES (?, ?)`, id, expires.Unix())
	if err != nil {
		return fmt.Errorf("record token use: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("record token use: %w", err)
	}
	if inserted == 0 {
		return ErrTokenUsed
	}
	return nil
}

// BackupTo writes a consistent copy of the database to path, which must
// not exist yet. It is safe while the server runs: SQLite copies one
// snapshot, and writers wait for it.
func (s *Store) BackupTo(ctx context.Context, path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return fmt.Errorf("back up the database: %w", err)
	}
	return os.Chmod(path, 0o600)
}

// Check runs SQLite's quick integrity check.
func (s *Store) Check(ctx context.Context) error {
	var result string
	if err := s.db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&result); err != nil {
		return fmt.Errorf("check the database: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("the database is damaged: %s", result)
	}
	return nil
}
