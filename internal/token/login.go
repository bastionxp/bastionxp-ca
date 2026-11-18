// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
)

// LoginValidity is how long a person has to finish a login at the
// identity provider.
const LoginValidity = 10 * time.Minute

// Login is what the CA has to remember while a person is away at the
// identity provider
// logging in: where to send them afterwards and what they asked for.
//
// The CA does not keep this in memory or in the database. It signs it,
// sends it along to the provider, and the provider hands it back unchanged with the
// result of the login. The signature proves that nobody altered it on
// the way.
type Login struct {
	// ID is unique for each login. Values that must stay secret while
	// the person is away (the PKCE verifier) are derived from it with
	// Derive, so they need not travel in this visible state.
	ID string `json:"id"`
	// Provider is the login it was started for, e.g. "oidc". A login
	// is refused at the callback of another provider.
	Provider string `json:"provider"`

	// Callback is the address on the person's own machine where the
	// result goes.
	Callback string `json:"callback"`
	// ClientState is a random value from the program that started the
	// login. It is sent back with the result, so the program can tell
	// its own login from somebody else's.
	ClientState string `json:"client_state"`

	// What the person asked for. Whether they may have it is decided
	// after the login, when the CA knows who they are.
	Template       string        `json:"profile"`
	Names          []string      `json:"names,omitempty"`
	Subject        string        `json:"subject,omitempty"`
	ValidFor       time.Duration `json:"valid_for,omitempty"`
	KeyFingerprint string        `json:"key,omitempty"`
}

// IssueLogin signs a Login, to carry it through a login at the provider.
func (v *Verifier) IssueLogin(login Login) (string, error) {
	if login.Callback == "" || login.ClientState == "" || login.Template == "" || login.Provider == "" {
		return "", errors.New("a login needs a callback, a client state, a profile and a provider")
	}
	if login.ID == "" {
		id, err := newID()
		if err != nil {
			return "", err
		}
		login.ID = id
	}
	now := v.now()
	return v.sign(jwt.Claims{
		Issuer:   issuer,
		Audience: jwt.Audience{audienceLogin},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(LoginValidity)),
	}, login)
}

// VerifyLogin checks the signature and expiry time of a signed Login and
// returns it. Every failure is reported as ErrInvalid.
func (v *Verifier) VerifyLogin(signed string) (*Login, error) {
	var standard jwt.Claims
	var login Login
	if err := v.parse(signed, audienceLogin, &standard, &login); err != nil {
		return nil, err
	}
	if login.Callback == "" || login.ClientState == "" || login.Template == "" || login.Provider == "" || login.ID == "" {
		return nil, fmt.Errorf("%w: a required field is missing", ErrInvalid)
	}
	return &login, nil
}

// Derive returns a secret that only this CA can compute again, for one
// purpose and one login ID: an HMAC with a key derived from the token
// key. It is URL-safe base64 of 32 bytes, 43 characters, which also fits
// the rules for a PKCE verifier.
func (v *Verifier) Derive(purpose, id string) string {
	mac := hmac.New(sha256.New, v.deriveKey)
	mac.Write([]byte(purpose))
	mac.Write([]byte{0})
	mac.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
