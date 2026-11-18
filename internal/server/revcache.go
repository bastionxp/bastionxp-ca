// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"sync"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// The CRL and the OCSP answers are public and need no login, and signing
// one costs real CPU. So the server keeps what it signed for a few
// minutes, instead of letting anybody make it sign in a loop.
//
// Revocations mostly do not come through the server: "bxp revoke"
// writes to the database directly. So WatchRevocations looks at the
// database every few seconds, drops the cached answers when something was
// revoked, and writes each new revocation to the log, so that the server's
// log has them all.

const (
	// revocationCheckEvery is how often the watcher looks for new
	// revocations: the most a revocation waits to show.
	revocationCheckEvery = 5 * time.Second
	// crlCacheFor and ocspCacheFor are how long a signed answer is
	// reused. Well inside their own validity (24 hours and 1 hour).
	crlCacheFor  = 5 * time.Minute
	ocspCacheFor = 5 * time.Minute
	// maxOCSPCache bounds the OCSP cache: questions about made-up
	// serial numbers must not fill the memory.
	maxOCSPCache = 10000
)

// revocationCache holds signed answers. Caching is on only while
// WatchRevocations runs, because only the watcher knows when they are out
// of date.
type revocationCache struct {
	mu       sync.Mutex
	watching bool
	crl      []byte
	crlUntil time.Time
	ocsp     map[string]cachedAnswer
}

type cachedAnswer struct {
	der   []byte
	until time.Time
}

func (c *revocationCache) getCRL(now time.Time) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.watching && now.Before(c.crlUntil) {
		return c.crl
	}
	return nil
}

func (c *revocationCache) putCRL(der []byte, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.watching {
		c.crl, c.crlUntil = der, now.Add(crlCacheFor)
	}
}

func (c *revocationCache) getOCSP(key string, now time.Time) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if a, ok := c.ocsp[key]; c.watching && ok && now.Before(a.until) {
		return a.der
	}
	return nil
}

func (c *revocationCache) putOCSP(key string, der []byte, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.watching {
		return
	}
	if c.ocsp == nil || len(c.ocsp) >= maxOCSPCache {
		c.ocsp = make(map[string]cachedAnswer)
	}
	c.ocsp[key] = cachedAnswer{der: der, until: now.Add(ocspCacheFor)}
}

func (c *revocationCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.crl, c.crlUntil, c.ocsp = nil, time.Time{}, nil
}

// revocationWatch is the watcher's memory between two looks.
type revocationWatch struct {
	state store.RevocationState
	// logged are the serials revoked in the second of state.Latest that
	// were already logged, so that a second look does not log them again.
	logged map[string]bool
}

// WatchRevocations turns on the caching of CRL and OCSP answers and keeps
// them up to date until ctx ends. It also logs revocations made while it
// runs. "bxp serve" runs it.
func (s *Server) WatchRevocations(ctx context.Context) {
	w, err := s.startWatch(ctx)
	if err != nil {
		s.log.Error("cannot watch revocations; CRL and OCSP answers are not cached", "error", err)
		return
	}
	ticker := time.NewTicker(revocationCheckEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.revocations.mu.Lock()
			s.revocations.watching = false
			s.revocations.mu.Unlock()
			return
		case <-ticker.C:
			s.checkRevocations(ctx, w)
		}
	}
}

// startWatch takes the first look, without logging what was revoked
// before, and turns caching on.
func (s *Server) startWatch(ctx context.Context) (*revocationWatch, error) {
	state, err := s.store.RevocationState(ctx)
	if err != nil {
		return nil, err
	}
	w := &revocationWatch{state: state, logged: map[string]bool{}}
	if state.Latest != 0 {
		certs, err := s.store.RevokedSince(ctx, time.Unix(state.Latest, 0))
		if err != nil {
			return nil, err
		}
		for _, c := range certs {
			w.logged[c.Kind+"/"+c.Serial] = true
		}
	}
	s.revocations.mu.Lock()
	s.revocations.watching = true
	s.revocations.mu.Unlock()
	return w, nil
}

// checkRevocations takes one look: if anything changed, it logs the new
// revocations and drops the cached answers.
func (s *Server) checkRevocations(ctx context.Context, w *revocationWatch) {
	state, err := s.store.RevocationState(ctx)
	if err != nil {
		// Without knowing, cached answers might be out of date.
		s.log.Error("cannot read revocations", "error", err)
		s.revocations.clear()
		return
	}
	if state == w.state {
		return
	}
	s.revocations.clear()
	if state.Latest >= w.state.Latest && state.Latest != 0 {
		certs, err := s.store.RevokedSince(ctx, time.Unix(w.state.Latest, 0))
		if err != nil {
			s.log.Error("cannot read revocations", "error", err)
		}
		logged := map[string]bool{}
		for _, c := range certs {
			key := c.Kind + "/" + c.Serial
			if c.RevokedAt.Unix() == state.Latest {
				logged[key] = true
			}
			if w.logged[key] {
				continue
			}
			s.log.Info("certificate revoked",
				"kind", c.Kind,
				"profile", c.Template,
				"serial", c.Serial,
				"subject", c.Subject,
				"names", c.Names,
				"reason", c.Reason,
				"revoked_at", c.RevokedAt.UTC().Format(time.RFC3339),
			)
		}
		if state.Latest == w.state.Latest {
			for key := range w.logged {
				logged[key] = true
			}
		}
		w.logged = logged
	}
	w.state = state
}
