// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// Every ACME request except the first two is a JWS: a JSON object with
// the real content ("payload"), some headers ("protected") and a
// signature made with the account's key. The headers say:
//
//	nonce  a value the server handed out, usable once
//	url    the address the request is meant for
//	kid    the address of the account that signed it, or
//	jwk    the public key itself, when the account does not exist yet

// maxBodyBytes limits the size of a request.
const maxBodyBytes = 128 * 1024

// signatureAlgorithms are the ways a request may be signed. All of them
// use a public and a private key. Anything else, in particular "none"
// and the algorithms with a shared secret, is refused.
var signatureAlgorithms = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512,
	jose.RS256, jose.PS256,
	jose.EdDSA,
}

// request is a signed request after all checks have passed.
type request struct {
	// account is who signed the request. It is nil only while the
	// account is being created.
	account *store.ACMEAccount
	// key is the public key the signature was checked with.
	key *jose.JSONWebKey
	// payload is the content. It is empty for a "POST-as-GET": a signed
	// request that only asks to see something.
	payload []byte
}

// decode reads the JSON payload into dest.
func (req *request) decode(dest any) error {
	if len(req.payload) == 0 {
		return errors.New("the request has no content")
	}
	return json.Unmarshal(req.payload, dest)
}

// signed wraps a handler for requests that must be signed by an existing
// account. The handler only runs if the signature is good.
func (s *Server) signed(next func(http.ResponseWriter, *http.Request, *request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, ok := s.readSigned(w, r, keyOfAccount)
		if !ok {
			return
		}
		next(w, r, req)
	}
}

// keySource says where the key of a signed request comes from.
type keySource int

const (
	// keyOfAccount: the request names its account ("kid"); every
	// request but new-account.
	keyOfAccount keySource = iota
	// keyInRequest: the key is in the request ("jwk"), for new-account.
	keyInRequest
	// keyOfAccountOrInRequest: either, for revoke-cert. A certificate
	// can be revoked by its account or with its own key.
	keyOfAccountOrInRequest
)

// readSigned reads and checks a signed request. On failure it sends the
// error answer itself and returns false.
func (s *Server) readSigned(w http.ResponseWriter, r *http.Request, source keySource) (*request, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "cannot read the request")
		return nil, false
	}
	jws, err := jose.ParseSigned(string(body), signatureAlgorithms)
	if err != nil {
		// go-jose refuses unknown algorithms while parsing.
		if strings.Contains(err.Error(), "algorithm") {
			s.writeProblem(w, r, http.StatusBadRequest, errBadSignatureAlg, "the request is signed with an algorithm this server does not accept")
			return nil, false
		}
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "the request is not a signed ACME request (JWS)")
		return nil, false
	}
	if len(jws.Signatures) != 1 {
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "the request must have exactly one signature")
		return nil, false
	}
	header := jws.Signatures[0].Protected

	// 1. Whose key?
	req := &request{}
	switch {
	case source == keyInRequest, source == keyOfAccountOrInRequest && header.JSONWebKey != nil:
		if header.JSONWebKey == nil || header.KeyID != "" {
			s.writeProblem(w, r, http.StatusBadRequest, errMalformed, `the request must carry the public key ("jwk") and no "kid"`)
			return nil, false
		}
		if !header.JSONWebKey.Valid() || !header.JSONWebKey.IsPublic() {
			s.writeProblem(w, r, http.StatusBadRequest, errBadPublicKey, "the account key is not a valid public key")
			return nil, false
		}
		req.key = header.JSONWebKey

	default:
		if header.KeyID == "" || header.JSONWebKey != nil {
			s.writeProblem(w, r, http.StatusBadRequest, errMalformed, `the request must name its account ("kid") and carry no "jwk"`)
			return nil, false
		}
		// The kid is the account's address. Take the ID from its end.
		id, isAccountURL := strings.CutPrefix(header.KeyID, s.accountURL(r, ""))
		if !isAccountURL || id == "" {
			s.writeProblem(w, r, http.StatusBadRequest, errAccountDoesNotExist, "no such account: "+header.KeyID)
			return nil, false
		}
		account, key, err := s.loadAccount(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			s.writeProblem(w, r, http.StatusBadRequest, errAccountDoesNotExist, "no such account: "+header.KeyID)
			return nil, false
		}
		if err != nil {
			s.writeInternalError(w, r, "cannot read account", err)
			return nil, false
		}
		req.account, req.key = account, key
	}

	// 2. Is the signature made with that key?
	req.payload, err = jws.Verify(req.key)
	if err != nil {
		s.writeProblem(w, r, http.StatusUnauthorized, errUnauthorized, "the signature of the request is not valid")
		return nil, false
	}
	// A closed account can do nothing more (RFC 8555, section 7.3.6).
	if req.account != nil && req.account.Status == store.ACMEAccountDeactivated {
		s.writeProblem(w, r, http.StatusUnauthorized, errUnauthorized, "this account was deactivated")
		return nil, false
	}

	// 3. Was the request made for this address? Without this check a
	// request signed for one endpoint could be sent to another.
	signedURL, _ := header.ExtraHeaders[jose.HeaderKey("url")].(string)
	if signedURL != s.baseURL(r)+r.URL.Path {
		s.writeProblem(w, r, http.StatusUnauthorized, errUnauthorized,
			`the "url" in the request is `+signedURL+", but it was sent to "+s.baseURL(r)+r.URL.Path)
		return nil, false
	}

	// 4. Is the nonce one of ours, and unused? This comes last, so that
	// only correctly signed requests can use up nonces.
	if !s.useNonce(header.Nonce) {
		s.writeProblem(w, r, http.StatusBadRequest, errBadNonce, "the nonce is unknown or was used before: try again with the new one")
		return nil, false
	}
	return req, true
}

// loadAccount reads an account and its public key.
func (s *Server) loadAccount(ctx context.Context, id string) (*store.ACMEAccount, *jose.JSONWebKey, error) {
	account, err := s.store.ACMEAccount(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	var key jose.JSONWebKey
	if err := json.Unmarshal([]byte(account.JWK), &key); err != nil {
		return nil, nil, err
	}
	return account, &key, nil
}

// thumbprint returns the fingerprint of an account key: the SHA-256 of
// the key in a fixed JSON form (RFC 7638), in URL-safe base64.
//
// It identifies an account by its key, and it is the part of a challenge
// answer that ties the answer to one account.
func thumbprint(key *jose.JSONWebKey) (string, error) {
	sum, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}
