// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"strconv"
	"time"
)

// CA are the counters of the certificate authority. A nil *CA counts
// nothing.
type CA struct {
	Registry *Registry
	issued   *CounterVec
	refused  *CounterVec
	logins   *CounterVec
	requests *SummaryVec
}

// NewCA returns the CA's counters in a new registry.
func NewCA() *CA {
	r := New()
	return &CA{
		Registry: r,
		issued: r.Counter("bastionxp_ca_certificates_issued_total",
			"Certificates issued, by kind and by how the requester was checked.", "kind", "verifier"),
		refused: r.Counter("bastionxp_ca_requests_refused_total",
			"Requests for a certificate or token that were refused, by reason.", "reason"),
		logins: r.Counter("bastionxp_ca_logins_total",
			"Logins with OIDC or LDAP, by method and result.", "method", "result"),
		requests: r.Summary("bastionxp_ca_http_request_duration_seconds",
			"HTTP requests and their duration, by route and status code.", "route", "code"),
	}
}

// Reasons a request is refused.
const (
	RefusedToken       = "invalid_token" // missing, invalid or expired token or proof
	RefusedUsed        = "token_used"    // the token was used before
	RefusedWrongKey    = "wrong_key"     // the token is for another key
	RefusedPolicy      = "not_allowed"   // names or profile the requester may not have
	RefusedUnsound     = "unsound"       // the CA refused it: weak key, lifetime, no name
	RefusedRateLimited = "rate_limited"  // too many requests from one source
)

// Results of a login.
const (
	LoginSuccess = "success"
	LoginFailed  = "failed"            // wrong credentials, or the login at the provider failed
	LoginNoRule  = "no_rule"           // the person is not in the access rules
	LoginTooMany = "too_many_failures" // the failure limit was reached
)

// Issued counts a certificate.
func (m *CA) Issued(kind, verifier string) {
	if m != nil {
		m.issued.Inc(kind, verifier)
	}
}

// Refused counts a refused request.
func (m *CA) Refused(reason string) {
	if m != nil {
		m.refused.Inc(reason)
	}
}

// Login counts a login.
func (m *CA) Login(method, result string) {
	if m != nil {
		m.logins.Inc(method, result)
	}
}

// Request counts an HTTP request.
func (m *CA) Request(route string, code int, took time.Duration) {
	if m != nil {
		m.requests.Observe(took.Seconds(), route, strconv.Itoa(code))
	}
}
