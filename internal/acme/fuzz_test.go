// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// The endpoints a signed request can go to.
var fuzzPaths = []string{
	"/acme/new-account", "/acme/new-order", "/acme/acct/x", "/acme/order/x",
	"/acme/order/x/finalize", "/acme/authz/x", "/acme/chall/x/http-01", "/acme/cert/x",
}

// FuzzACME sends arbitrary bodies to every signed ACME endpoint. Nobody
// needs a login to send these, so the server must never panic and never
// answer with a server error.
func FuzzACME(f *testing.F) {
	env := newTestEnv(f)
	handler := env.server.Handler()

	// A properly signed new-account request, for the fuzzer to change.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	nonce, err := env.server.newNonce()
	if err != nil {
		f.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, &jose.SignerOptions{
		EmbedJWK:     true,
		ExtraHeaders: map[jose.HeaderKey]any{"nonce": nonce, "url": "https://example.com/acme/new-account"},
	})
	if err != nil {
		f.Fatal(err)
	}
	signed, err := signer.Sign([]byte(`{"termsOfServiceAgreed":true}`))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(0), []byte(signed.FullSerialize()))
	f.Add(uint8(1), []byte(`{"protected":"e30","payload":"","signature":""}`))
	f.Add(uint8(4), []byte(`{}`))
	f.Add(uint8(6), []byte(`[]`))

	f.Fuzz(func(t *testing.T, which uint8, body []byte) {
		path := fuzzPaths[int(which)%len(fuzzPaths)]
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/jose+json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("POST %s: status %d (%s)", path, rec.Code, rec.Body)
		}
	})
}
