// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package scep

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
)

// fuzzServer is a SCEP server that issues nothing: what matters here is
// how it reads what it is sent.
func fuzzServer(f *testing.F) (*Server, *RA) { return fuzzServerT(f) }

func fuzzServerT(f testing.TB) (*Server, *RA) {
	f.Helper()
	dir := f.TempDir()
	if err := ca.Init(dir, ca.InitOptions{Name: "Test", Organization: "Test Org", KeyType: ca.KeyTypeECDSA}); err != nil {
		f.Fatal(err)
	}
	authority, err := ca.Load(dir, nil)
	if err != nil {
		f.Fatal(err)
	}
	ra, err := LoadOrCreateRA(dir, authority)
	if err != nil {
		f.Fatal(err)
	}
	server := New(Options{
		RA:      ra,
		CACerts: []*x509.Certificate{authority.IntermediateCert(), authority.RootCert()},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Issue: func(context.Context, string, *x509.CertificateRequest, string) (*x509.Certificate, error) {
			return nil, errors.New("not in this test")
		},
	})
	return server, ra
}

// FuzzPKIOperation sends arbitrary messages to the SCEP endpoint. The
// server must never panic, and never answer with a server error: a
// message it cannot read is the sender's fault.
func FuzzPKIOperation(f *testing.F) {
	server, ra := fuzzServer(f)
	key := newRSAKey(f)
	csr, err := NewCSR(csrTemplate("device-1"), key, "a-challenge")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(buildMessage(f, key, ra.Cert, csr, messagePKCSReq))
	f.Add(buildMessage(f, key, ra.Cert, []byte("not a CSR"), messagePKCSReq))
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x80})
	f.Fuzz(func(t *testing.T, body []byte) {
		rec := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			defer close(done)
			server.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/scep?operation=PKIOperation", bytes.NewReader(body)))
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("a message of %d bytes did not finish in 2 seconds", len(body))
		}
		if rec.Code >= 500 {
			t.Fatalf("status %d for a message of %d bytes", rec.Code, len(body))
		}
	})
}

// Messages with a few random bytes changed: the server answers each fast,
// and never with a server error. (Go's fuzzing engine is slow on this
// target, so this runs a plain loop as well, on every test run.)
func TestMutatedMessages(t *testing.T) {
	server, ra := fuzzServerT(t)
	key := newRSAKey(t)
	csr, err := NewCSR(csrTemplate("device-1"), key, "a-challenge")
	if err != nil {
		t.Fatal(err)
	}
	seed := buildMessage(t, key, ra.Cert, csr, messagePKCSReq)
	r := rand.New(rand.NewPCG(1, 2)) // the same messages every run
	for range 2000 {
		body := bytes.Clone(seed)
		for range 1 + r.IntN(4) {
			body[r.IntN(len(body))] = byte(r.IntN(256))
		}
		start := time.Now()
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/scep?operation=PKIOperation", bytes.NewReader(body)))
		if took := time.Since(start); took > time.Second {
			t.Fatalf("a message took %s", took)
		}
		if rec.Code >= 500 {
			t.Fatalf("status %d", rec.Code)
		}
	}
}

// FuzzChallenge reads the challenge password out of arbitrary CSRs.
func FuzzChallenge(f *testing.F) {
	key := newRSAKey(f)
	csr, err := NewCSR(csrTemplate("device-1"), key, "a-challenge")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(csr)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, der []byte) {
		_ = Challenge(der)
	})
}
