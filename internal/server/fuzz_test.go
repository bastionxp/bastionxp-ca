// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/ocsp"

	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/client"
)

// FuzzOCSP sends arbitrary OCSP requests, as a POST body and at the end of
// a GET address. The answer is never a server error, and always an OCSP
// answer.
func FuzzOCSP(f *testing.F) {
	env := newTestEnv(f)
	cert := env.issue(f, "web.example.com")
	req, err := ocsp.CreateRequest(cert, env.ca.IntermediateCert(), nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(req, "")
	f.Add([]byte{}, "MEMwQTA/MD0wOzAJBgUrDgMCGgUABBQ")
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00}, "%2F%2F")
	f.Fuzz(func(t *testing.T, body []byte, path string) {
		rec := httptest.NewRecorder()
		env.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, ca.OCSPPath, bytes.NewReader(body)))
		if rec.Code >= 500 || rec.Header().Get("Content-Type") != "application/ocsp-response" {
			t.Fatalf("POST: status %d, type %q", rec.Code, rec.Header().Get("Content-Type"))
		}
		if _, err := url.ParseRequestURI(ca.OCSPPath + "/" + path); err != nil || strings.ContainsAny(path, " ?#") {
			return // the HTTP server refuses such an address before any handler
		}
		rec = httptest.NewRecorder()
		env.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ca.OCSPPath+"/"+path, nil))
		if rec.Code >= 500 {
			t.Fatalf("GET %q: status %d", path, rec.Code)
		}
	})
}

// FuzzCSR reads arbitrary CSRs the way the sign endpoint does. Whatever
// is accepted must carry a valid signature: proof that the requester
// holds the key.
func FuzzCSR(f *testing.F) {
	f.Add(newCSR(f, "web.example.com", "web.example.com", "10.0.0.5"))
	f.Add("-----BEGIN CERTIFICATE REQUEST-----\nMAA=\n-----END CERTIFICATE REQUEST-----\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, pemText string) {
		csr, err := parseCSR(pemText)
		if err != nil {
			return
		}
		if _, err := ca.RequestFromCSR(ca.TLSServer, csr); err == nil && csr.CheckSignature() != nil {
			t.Fatal("accepted a CSR with a bad signature")
		}
	})
}

// FuzzRenew sends arbitrary renewal proofs and bodies. The answer is never
// a server error, and a certificate is issued only for a proof really
// signed with a certificate's key, which only the seed is.
func FuzzRenew(f *testing.F) {
	env := newTestEnv(f)
	old, key := env.issueWithKey(f, "tls-server", "48h", "web.example.com")
	body := renewBody(f, "web.example.com")
	valid := mustProof(f, client.Proof{Key: key, X509: old, Body: body})
	f.Add(valid, body)
	f.Add("", body)
	f.Add("a.b.c", []byte("{}"))
	f.Fuzz(func(t *testing.T, proof string, body []byte) {
		if strings.ContainsAny(proof, "\r\n") {
			return // not a header value
		}
		for _, path := range []string{api.RenewX509Path, api.RenewSSHPath} {
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+proof)
			rec := httptest.NewRecorder()
			env.handler.ServeHTTP(rec, req)
			if rec.Code >= 500 {
				t.Fatalf("%s: status %d (%s)", path, rec.Code, rec.Body)
			}
			if rec.Code == http.StatusCreated && proof != valid {
				t.Fatalf("%s: a certificate for a proof that was not signed: %q", path, proof)
			}
		}
	})
}
