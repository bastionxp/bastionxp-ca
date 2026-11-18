// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// challengeTimeout is how long the whole request to the client's host
// may take.
const challengeTimeout = 10 * time.Second

// checkHTTP01 fetches http://<name>/.well-known/acme-challenge/<token>
// and compares the answer with want. It returns nil if they match and a
// problem that explains the failure otherwise.
//
// The client was told the token, and only the account that asked can
// build the right answer (it contains the fingerprint of its key). So a
// right answer at that address means: the holder of the account key
// controls what the host serves on port 80.
func (s *Server) checkHTTP01(ctx context.Context, name, token, want string) *problem {
	client := &http.Client{
		Timeout: challengeTimeout,
		Transport: &http.Transport{
			DialContext:       s.dial,
			DisableKeepAlives: true,
		},
		// Do not follow redirects. A host that sends us elsewhere has
		// not shown that it can serve the answer itself, and following
		// would let it point this server at any address it likes.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	host := name
	if ip := net.ParseIP(name); ip != nil && ip.To4() == nil {
		host = "[" + name + "]" // IPv6, in a URL
	}
	address := "http://" + host + "/.well-known/acme-challenge/" + token
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return newProblem(errConnection, "cannot build the request to "+address)
	}
	resp, err := client.Do(req)
	if err != nil {
		return newProblem(errConnection, fmt.Sprintf("cannot fetch %s: %v", address, err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return newProblem(errIncorrectResponse, fmt.Sprintf("%s answered with status %d, want 200", address, resp.StatusCode))
	}
	// The right answer is under 100 bytes. Never read more than a little.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return newProblem(errConnection, fmt.Sprintf("cannot read the answer of %s: %v", address, err))
	}
	if strings.TrimSpace(string(body)) != want {
		return newProblem(errIncorrectResponse, address+" did not return the expected text")
	}
	return nil
}
