// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"net"
	"slices"
	"strings"
)

// The ways a client can prove that it controls a name. Each authorization
// offers all that fit its name; the client answers one of them.
//
//	http-01      a file at http://<name>/.well-known/acme-challenge/<token>
//	dns-01       a TXT record at _acme-challenge.<name>
//	tls-alpn-01  a special certificate on port 443 of <name>
//
// A wildcard name (*.example.com) is proved with dns-01 only: control of
// the DNS of example.com is what covers every name below it (RFC 8555,
// section 7.1.3).
const (
	challengeHTTP01    = "http-01"
	challengeDNS01     = "dns-01"
	challengeTLSALPN01 = "tls-alpn-01"
)

// ChallengeTypes are all the challenge types this server knows.
var ChallengeTypes = []string{challengeHTTP01, challengeDNS01, challengeTLSALPN01}

// SetChallenges replaces the challenge types the server offers; empty
// means all. Pending authorizations can then only use the new ones.
func (s *Server) SetChallenges(types []string) {
	allowed := slices.Clone(types)
	if len(allowed) == 0 {
		allowed = slices.Clone(ChallengeTypes)
	}
	s.challenges.Store(&allowed)
}

// challengesFor returns the challenge types offered for a name: those
// that can prove it, and that the administrator allows.
func (s *Server) challengesFor(name string) []string {
	possible := ChallengeTypes
	switch {
	case isWildcard(name):
		possible = []string{challengeDNS01}
	case net.ParseIP(name) != nil:
		// RFC 8738: an IP address has no DNS of its own to prove.
		possible = []string{challengeHTTP01, challengeTLSALPN01}
	}
	allowed := *s.challenges.Load()
	var offered []string
	for _, c := range possible {
		if slices.Contains(allowed, c) {
			offered = append(offered, c)
		}
	}
	return offered
}

func (s *Server) offers(name, challenge string) bool {
	return slices.Contains(s.challengesFor(name), challenge)
}

func isWildcard(name string) bool { return strings.HasPrefix(name, "*.") }

// check runs one challenge: nil if the client proved control of name,
// otherwise a problem that says why not. keyAuth is the "key
// authorization": the token and the fingerprint of the account key. Only
// the account that asked can build it.
func (s *Server) check(ctx context.Context, challenge, name, token, keyAuth string) *problem {
	switch challenge {
	case challengeHTTP01:
		return s.checkHTTP01(ctx, name, token, keyAuth)
	case challengeDNS01:
		return s.checkDNS01(ctx, strings.TrimPrefix(name, "*."), keyAuth)
	case challengeTLSALPN01:
		return s.checkTLSALPN01(ctx, name, keyAuth)
	default:
		return newProblem(errMalformed, "unknown challenge type "+challenge)
	}
}
