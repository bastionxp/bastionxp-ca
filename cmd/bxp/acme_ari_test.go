// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"golang.org/x/crypto/acme"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// "bxp acme renew" asks BastionXP CA when to renew: not yet for a fresh
// certificate, at once once it is revoked, without --force.
func TestACMERenewAsksTheCA(t *testing.T) {
	testCA := startTestCA(t)
	certFile, keyFile := issueForTest(t, testCA, "web.example.com")
	before, _ := tls.LoadX509KeyPair(certFile, keyFile)
	address := freeAddress(t)
	testCA.acme.set(address)
	opts := acmeRenewOptions{cert: certFile, key: keyFile, httpAddress: address}

	var out bytes.Buffer
	if err := runACMERenew(context.Background(), &out, io.Discard, testCA.acmeConn(), opts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Not yet:      valid until") || !strings.Contains(out.String(), "the CA suggests renewing between") {
		t.Errorf("a fresh certificate:\n%s", out.String())
	}

	leaf, _ := x509.ParseCertificate(before.Certificate[0])
	if err := runRevoke(context.Background(), io.Discard, testCA.cfg, leaf.SerialNumber.Text(16), "key-compromise", false); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runACMERenew(context.Background(), &out, io.Discard, testCA.acmeConn(), opts); err != nil {
		t.Fatal(err)
	}
	after, _ := tls.LoadX509KeyPair(certFile, keyFile)
	if bytes.Equal(after.Certificate[0], before.Certificate[0]) {
		t.Errorf("a revoked certificate was not renewed:\n%s", out.String())
	}
}

// A CA without renewal information: the usual rule, a third of the
// lifetime.
func TestACMERenewalDueWithoutRenewalInfo(t *testing.T) {
	fake := startFakeACME(t)
	now := time.Now()
	cert := &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(23 * time.Hour), AuthorityKeyId: []byte{1}}
	conn := connection{root: fake.root}
	due, notYet := acmeRenewalDue(context.Background(), conn, fake.server.URL+"/dir", cert, now)
	if due || !strings.Contains(notYet, "renews from") {
		t.Errorf("fresh: due = %v, %q", due, notYet)
	}
	cert.NotBefore, cert.NotAfter = now.Add(-20*time.Hour), now.Add(4*time.Hour)
	if due, _ := acmeRenewalDue(context.Background(), conn, fake.server.URL+"/dir", cert, now); !due {
		t.Error("with less than a third left: not due")
	}
}

// A rate limit from the CA is explained with its message and when to try
// again (Retry-After as seconds or a date), and is not retried; a passing
// server error is retried; other errors are left as they are.
func TestExplainACMERateLimit(t *testing.T) {
	limited := &acme.Error{StatusCode: 429, Detail: "too many new orders for this account",
		Header: http.Header{"Retry-After": []string{"3600"}}}
	msg := explainACMEError(fmt.Errorf("order: %w", limited)).Error()
	if !strings.Contains(msg, "too many new orders for this account") || !strings.Contains(msg, "in 1h0m0s") {
		t.Errorf("message: %q", msg)
	}
	other := errors.New("something else")
	if explainACMEError(other) != other {
		t.Error("another error was changed")
	}
	now := time.Now()
	if d := retryAfter(http.Header{"Retry-After": []string{now.Add(30 * time.Minute).UTC().Format(http.TimeFormat)}}, now); d < 29*time.Minute || d > 31*time.Minute {
		t.Errorf("Retry-After as a date: %v", d)
	}
	if acmeRetry(1, nil, &http.Response{StatusCode: 429}) > 0 {
		t.Error("a rate limit is waited for")
	}
	if acmeRetry(1, nil, &http.Response{StatusCode: 503}) <= 0 {
		t.Error("a passing server error is not tried again")
	}
}
