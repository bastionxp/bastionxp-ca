// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"net"
	"sync"
	"time"
)

// Anybody who can reach the CA can talk ACME, without a login. These
// limits keep one source from filling the database or keeping the CA busy
// with challenge requests. They are in memory: a restart forgets them.
const (
	limitWindow         = time.Hour
	maxTrackedLimitKeys = 10000
)

// Limits are the most new accounts per IP address and new orders per
// account, each per hour. Zero means no limit.
type Limits struct {
	AccountsPerIP    int
	OrdersPerAccount int
}

// DefaultLimits are used where the configuration says nothing.
var DefaultLimits = Limits{AccountsPerIP: 100, OrdersPerAccount: 300}

// SetLimits replaces the limits. Counts so far are kept.
func (s *Server) SetLimits(limits Limits) {
	s.accountsPerIP.setMax(limits.AccountsPerIP)
	s.ordersPerAccount.setMax(limits.OrdersPerAccount)
}

// windowLimiter counts events per key within the window.
type windowLimiter struct {
	mu     sync.Mutex
	max    int
	events map[string][]time.Time
	now    func() time.Time
}

func newWindowLimiter(max int) *windowLimiter {
	return &windowLimiter{max: max, events: make(map[string][]time.Time), now: time.Now}
}

func (l *windowLimiter) setMax(max int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.max = max
}

// full reports whether key has used up its events, and when the next one
// would be allowed. With max 0 it never is.
func (l *windowLimiter) full(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.max <= 0 {
		return false, 0
	}
	now := l.now()
	kept := l.recent(key, now)
	if len(kept) < l.max {
		return false, 0
	}
	return true, kept[0].Add(limitWindow).Sub(now)
}

// add counts one event for key.
func (l *windowLimiter) add(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.max <= 0 {
		return
	}
	now := l.now()
	if len(l.events) >= maxTrackedLimitKeys {
		for k := range l.events {
			l.recent(k, now)
		}
	}
	l.events[key] = append(l.recent(key, now), now)
}

func (l *windowLimiter) recent(key string, now time.Time) []time.Time {
	var kept []time.Time
	for _, t := range l.events[key] {
		if now.Sub(t) < limitWindow {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(l.events, key)
	} else {
		l.events[key] = kept
	}
	return kept
}

// hostOf drops the port from a remote address.
func hostOf(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return remote
}
