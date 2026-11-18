// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ldap

import (
	"strings"
	"sync"
	"time"
)

// The CA passes every login on to the directory, and directories lock an
// account after a few wrong passwords. Without a limit here, anybody could
// lock people out of the directory, and so out of their whole company
// account, by sending wrong passwords to the CA.
//
// The limits are below what directories usually lock at (often 5 to 10
// failures), and per address too, so one source cannot try many names.
const (
	failureWindow   = 15 * time.Minute
	maxUserFailures = 3  // per username in the window
	maxAddrFailures = 20 // per address in the window
	maxTracked      = 10000
)

// limiter counts failed logins. It is in memory: a restart forgets.
type limiter struct {
	mu    sync.Mutex
	users map[string][]time.Time
	addrs map[string][]time.Time
	now   func() time.Time
}

func newLimiter() *limiter {
	return &limiter{users: make(map[string][]time.Time), addrs: make(map[string][]time.Time), now: time.Now}
}

// allow reports whether a login may be tried.
func (l *limiter) allow(username, addr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	return len(recent(l.users, strings.ToLower(username), now)) < maxUserFailures &&
		len(recent(l.addrs, hostOf(addr), now)) < maxAddrFailures
}

func (l *limiter) failed(username, addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.users) > maxTracked || len(l.addrs) > maxTracked {
		l.forgetOld(now)
	}
	key := strings.ToLower(username)
	l.users[key] = append(recent(l.users, key, now), now)
	host := hostOf(addr)
	l.addrs[host] = append(recent(l.addrs, host, now), now)
}

// succeeded clears the failures of a username: the person knows their
// password after all.
func (l *limiter) succeeded(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.users, strings.ToLower(username))
}

// recent returns the failures of key inside the window.
func recent(m map[string][]time.Time, key string, now time.Time) []time.Time {
	var kept []time.Time
	for _, t := range m[key] {
		if now.Sub(t) < failureWindow {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(m, key)
	} else {
		m[key] = kept
	}
	return kept
}

func (l *limiter) forgetOld(now time.Time) {
	for key := range l.users {
		recent(l.users, key, now)
	}
	for key := range l.addrs {
		recent(l.addrs, key, now)
	}
}

// hostOf drops the port from an address such as "10.0.0.5:51234".
func hostOf(addr string) string {
	if i := strings.LastIndex(addr, ":"); i > 0 && !strings.HasSuffix(addr, "]") {
		return addr[:i]
	}
	return addr
}
