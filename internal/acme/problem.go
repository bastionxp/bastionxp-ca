// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/metrics"
)

// A problem is an error answer. ACME uses the "problem document" format
// (RFC 7807), with a type that tells the client what kind of error it is.

// The error types this server uses. Each is prefixed with
// "urn:ietf:params:acme:error:" in the answer.
const (
	errMalformed             = "malformed"             // the request makes no sense
	errBadNonce              = "badNonce"              // the client should retry with a new nonce
	errBadSignatureAlg       = "badSignatureAlgorithm" // signed with something we do not accept
	errBadPublicKey          = "badPublicKey"          // the account key is not usable
	errUnauthorized          = "unauthorized"          // not allowed, or not the client's
	errAccountDoesNotExist   = "accountDoesNotExist"   // no account for this key
	errRejectedIdentifier    = "rejectedIdentifier"    // the CA will not issue for this name
	errUnsupportedIdentifier = "unsupportedIdentifier" // not a DNS name
	errOrderNotReady         = "orderNotReady"         // finalize came too early
	errBadCSR                = "badCSR"                // the CSR does not fit the order
	errConnection            = "connection"            // the challenge address cannot be reached
	errIncorrectResponse     = "incorrectResponse"     // the challenge address gave a wrong answer
	errDNS                   = "dns"                   // the DNS lookup for dns-01 failed
	errTLS                   = "tls"                   // the TLS connection for tls-alpn-01 failed
	errRateLimited           = "rateLimited"           // too many requests; try again later
	errServerInternal        = "serverInternal"        // our fault
	errAlreadyRevoked        = "alreadyRevoked"        // revoked before
	errBadRevocationReason   = "badRevocationReason"   // a reason this CA does not use
	errAlreadyReplaced       = "alreadyReplaced"       // another order already renews the certificate (RFC 9773)
)

// problem is the body of an error answer.
type problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status,omitempty"`
}

func newProblem(kind, detail string) *problem {
	return &problem{Type: "urn:ietf:params:acme:error:" + kind, Detail: detail}
}

// writeProblem sends an error answer.
func (s *Server) writeProblem(w http.ResponseWriter, r *http.Request, status int, kind, detail string) {
	p := newProblem(kind, detail)
	p.Status = status
	s.addCommonHeaders(w, r)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)
}

// writeInternalError logs err and tells the client only that something
// went wrong on our side.
func (s *Server) writeInternalError(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.log.Error("ACME: "+what, "error", err)
	s.writeProblem(w, r, http.StatusInternalServerError, errServerInternal, "internal error")
}

// writeJSON sends a normal answer.
func (s *Server) writeJSON(w http.ResponseWriter, r *http.Request, status int, value any) {
	s.addCommonHeaders(w, r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// addCommonHeaders sets what every ACME answer carries: a fresh nonce
// for the client's next request, and a pointer to the directory.
func (s *Server) addCommonHeaders(w http.ResponseWriter, r *http.Request) {
	if nonce, err := s.newNonce(); err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Add("Link", "<"+s.baseURL(r)+DirectoryPath+`>;rel="index"`)
}

// rateLimited answers a request over one of the limits, and says when to
// try again.
func (s *Server) rateLimited(w http.ResponseWriter, r *http.Request, retry time.Duration, detail string) {
	s.metrics.Refused(metrics.RefusedRateLimited)
	s.log.Warn("ACME request refused: rate limit", "detail", detail, "remote", r.RemoteAddr)
	w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
	s.writeProblem(w, r, http.StatusTooManyRequests, errRateLimited, detail+"; try again later")
}
