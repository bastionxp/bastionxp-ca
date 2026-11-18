// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/api"
)

// Proof describes a renewal proof: what a renew request carries instead
// of a one-time token. See api.ProofAudienceX509 for what it is.
type Proof struct {
	// Key is the private key of the certificate being renewed.
	Key crypto.Signer
	// X509 or SSH is that certificate. Set exactly one.
	X509 *x509.Certificate
	SSH  *ssh.Certificate
	// Body is the request body the proof is for.
	Body []byte

	// The rest has good defaults. Tests change them.
	Audience string        // default: from the kind of certificate
	Lifetime time.Duration // default: one minute
	Now      time.Time     // default: now
}

// Sign returns the proof as a JWT.
func (p Proof) Sign() (string, error) {
	if (p.X509 == nil) == (p.SSH == nil) {
		return "", errors.New("a proof is for exactly one certificate")
	}
	algorithm, key, err := signingKey(p.Key)
	if err != nil {
		return "", err
	}

	options := &jose.SignerOptions{}
	options.WithType("JWT")
	audience := p.Audience
	if p.X509 != nil {
		options.WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(p.X509.Raw)})
		if audience == "" {
			audience = api.ProofAudienceX509
		}
	} else {
		options.WithHeader(api.ProofSSHCertHeader, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(p.SSH))))
		if audience == "" {
			audience = api.ProofAudienceSSH
		}
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: key}, options)
	if err != nil {
		return "", err
	}

	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	lifetime := p.Lifetime
	if lifetime == 0 {
		lifetime = time.Minute
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	sum := sha256.Sum256(p.Body)
	return jwt.Signed(signer).
		Claims(jwt.Claims{
			Audience: jwt.Audience{audience},
			ID:       hex.EncodeToString(id[:]),
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(lifetime)),
		}).
		Claims(api.ProofClaims{BodySHA256: base64.RawURLEncoding.EncodeToString(sum[:])}).
		Serialize()
}

// signingKey returns the JWS algorithm for a key, and the key in the form
// the JWS library wants.
func signingKey(key crypto.Signer) (jose.SignatureAlgorithm, any, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return jose.ES256, k, nil
		case elliptic.P384():
			return jose.ES384, k, nil
		case elliptic.P521():
			return jose.ES512, k, nil
		}
	case *rsa.PrivateKey:
		return jose.RS256, k, nil
	case ed25519.PrivateKey:
		return jose.EdDSA, k, nil
	}
	return "", nil, fmt.Errorf("a key of type %T cannot sign a renewal proof", key)
}
