// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
)

// syncBuffer is a log destination that tests can read while the server
// writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// watched is a test CA with the revocation watcher's first look taken.
func watched(t *testing.T) (*testEnv, *revocationWatch, *syncBuffer) {
	t.Helper()
	env := newTestEnv(t)
	var logs syncBuffer
	env.server.log = slog.New(slog.NewTextHandler(&logs, nil))
	w, err := env.server.startWatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return env, w, &logs
}

// The CRL is signed once and cached, with Cache-Control, until a revocation;
// a revocation made by another process (bxp revoke) is picked up at the
// watcher's next look, and logged once.
func TestCRLIsCachedUntilARevocation(t *testing.T) {
	env, w, logs := watched(t)
	cert := env.issue(t, "web.example.com")

	first := fetch(t, env.handler, ca.CRLPath)
	if first.Header().Get("Cache-Control") != "public, max-age=300" {
		t.Errorf("Cache-Control = %q", first.Header().Get("Cache-Control"))
	}
	time.Sleep(1100 * time.Millisecond) // a new CRL would have a new number
	if second := fetch(t, env.handler, ca.CRLPath); !bytes.Equal(first.Body.Bytes(), second.Body.Bytes()) {
		t.Error("the CRL was signed again instead of reused")
	}

	// "bxp revoke", then the watcher's next look.
	env.revoke(t, cert, ca.ReasonKeyCompromise)
	if onCRL(env.crl(t), cert) != nil {
		t.Fatal("test setup: the cached CRL already has the revocation")
	}
	env.server.checkRevocations(context.Background(), w)
	if onCRL(env.crl(t), cert) == nil {
		t.Error("after the watcher's look, the CRL still lacks the revocation")
	}
	if !strings.Contains(logs.String(), "certificate revoked") || !strings.Contains(logs.String(), cert.SerialNumber.Text(16)) {
		t.Errorf("the revocation is not in the log:\n%s", logs)
	}

	// The next look logs nothing new.
	before := strings.Count(logs.String(), "certificate revoked")
	env.server.checkRevocations(context.Background(), w)
	if after := strings.Count(logs.String(), "certificate revoked"); after != before {
		t.Errorf("the revocation was logged %d times", after)
	}
}

// OCSP answers are cached, and a revocation made by another process shows in
// them after the watcher's next look.
func TestOCSPIsCachedUntilARevocation(t *testing.T) {
	env, w, _ := watched(t)
	cert := env.issue(t, "web.example.com")
	issuer := env.ca.IntermediateCert()

	if s := env.ocspStatus(t, cert, issuer); s.Status != ocsp.Good {
		t.Fatalf("status %d, want good", s.Status)
	}
	env.revoke(t, cert, ca.ReasonKeyCompromise)
	if s := env.ocspStatus(t, cert, issuer); s.Status != ocsp.Good {
		t.Fatal("test setup: the answer was not cached")
	}
	env.server.checkRevocations(context.Background(), w)
	if s := env.ocspStatus(t, cert, issuer); s.Status != ocsp.Revoked {
		t.Errorf("after the watcher's look: status %d, want revoked", s.Status)
	}
}

// Revocations from before the server started are not logged again.
func TestWatcherDoesNotLogOldRevocations(t *testing.T) {
	env := newTestEnv(t)
	cert := env.issue(t, "web.example.com")
	env.revoke(t, cert, ca.ReasonSuperseded)
	var logs syncBuffer
	env.server.log = slog.New(slog.NewTextHandler(&logs, nil))
	w, err := env.server.startWatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	env.server.checkRevocations(context.Background(), w)
	if strings.Contains(logs.String(), "certificate revoked") {
		t.Errorf("an old revocation was logged:\n%s", logs.String())
	}
}

// Questions about made-up serial numbers cannot fill the memory.
func TestOCSPCacheIsBounded(t *testing.T) {
	var c revocationCache
	c.watching = true
	now := time.Now()
	for i := range maxOCSPCache + 10 {
		c.putOCSP(strings.Repeat("x", i%7)+string(rune(i)), []byte("a"), now)
	}
	if len(c.ocsp) > maxOCSPCache {
		t.Errorf("cache has %d entries, limit %d", len(c.ocsp), maxOCSPCache)
	}
}

// The watcher stops with its context, and caching with it.
func TestWatchRevocationsStops(t *testing.T) {
	env := newTestEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { env.server.WatchRevocations(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher did not stop")
	}
	if env.server.revocations.getCRL(time.Now()) != nil || env.server.revocations.watching {
		t.Error("caching is still on")
	}
}
