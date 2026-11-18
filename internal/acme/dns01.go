// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
)

// checkDNS01 looks for the TXT record _acme-challenge.<name> with the
// SHA-256 of the key authorization, in URL-safe base64 (RFC 8555, section
// 8.4). The record means: the holder of the account key controls the DNS
// of name.
func (s *Server) checkDNS01(ctx context.Context, name, keyAuth string) *problem {
	sum := sha256.Sum256([]byte(keyAuth))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	record := "_acme-challenge." + name + "."

	ctx, cancel := context.WithTimeout(ctx, challengeTimeout)
	defer cancel()
	values, err := s.lookupTXT(ctx, record)
	if err != nil {
		return newProblem(errDNS, fmt.Sprintf("cannot look up the TXT record %s: %v", record, err))
	}
	for _, v := range values {
		if strings.TrimSpace(v) == want {
			return nil
		}
	}
	return newProblem(errIncorrectResponse, fmt.Sprintf("no TXT record %s with the expected value (found %d)", record, len(values)))
}

// directResolver asks one DNS server, e.g. "10.0.0.53:53", instead of the
// ones the machine is set up with. Asking the server that holds the zone
// avoids caches that still remember "no such record" from before the
// client created it.
func directResolver(server string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// network is "udp", or "tcp" for an answer too large for UDP.
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, server)
		},
	}
}
