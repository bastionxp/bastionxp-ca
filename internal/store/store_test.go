// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func openTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), FileName)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

// A token can be used once; another token is not affected.
func TestUseTokenOnlyWorksOnce(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)

	if err := s.UseToken(ctx, "token-1", expires); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := s.UseToken(ctx, "token-1", expires); !errors.Is(err, ErrTokenUsed) {
		t.Errorf("second use: error = %v, want ErrTokenUsed", err)
	}
	// A different token is not affected.
	if err := s.UseToken(ctx, "token-2", expires); err != nil {
		t.Errorf("other token: %v", err)
	}
}

// A used token stays used after the database is reopened.
func TestUseTokenIsRememberedAfterRestart(t *testing.T) {
	s, path := openTestStore(t)
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)

	if err := s.UseToken(ctx, "token-1", expires); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.UseToken(ctx, "token-1", expires); !errors.Is(err, ErrTokenUsed) {
		t.Errorf("after reopening: error = %v, want ErrTokenUsed", err)
	}
}

// Many uses of one token at the same time: exactly one succeeds.
func TestUseTokenWithManyRequestsAtOnce(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)

	const attempts = 20
	errs := make([]error, attempts)
	var wg sync.WaitGroup
	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.UseToken(ctx, "token-1", expires)
		}()
	}
	wg.Wait()

	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, ErrTokenUsed):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if won != 1 {
		t.Errorf("%d requests used the token, want exactly 1", won)
	}
}

// Records of expired tokens are removed.
func TestUseTokenRemovesExpiredRecords(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	if err := s.UseToken(ctx, "old", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.UseToken(ctx, "new", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM used_tokens`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("%d records left, want 1 (the expired one should be gone)", count)
	}
}

// A token without an ID is refused.
func TestUseTokenRejectsEmptyID(t *testing.T) {
	s, _ := openTestStore(t)
	if err := s.UseToken(context.Background(), "", time.Now().Add(time.Hour)); err == nil {
		t.Error("expected an error for an empty ID, got nil")
	}
}
