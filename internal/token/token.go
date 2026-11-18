// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package token is the one-time token verifier.
//
// An administrator creates a token on the CA machine with "bxp token".
// The token says which certificate template and which names its holder may
// request, and who it was made for. The holder sends it with a certificate request, and the server
// checks it with Verify.
//
// A token is a JWT signed with the key in the data directory (token.key).
// Anyone who can read that file can create tokens, so it is as sensitive
// as the CA keys.
//
// This package checks the signature and the expiry time. Making sure a
// token is used only once is done by the caller, with the store package,
// because it needs a database.
package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unicode"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/bastionxp/bastionxp-ca/internal/keyfile"
)

// KeyFile is the name of the token signing key inside the data directory.
const KeyFile = "token.key"

const (
	// DefaultValidity is how long a token is valid when nothing else is asked for.
	DefaultValidity = 10 * time.Minute
	// MaxValidity is the longest a token may be valid. Tokens are meant to
	// be used right away, so this is short.
	MaxValidity = 24 * time.Hour

	// issuer is written into every token and checked on the way back.
	issuer = "bastionxp-ca"
)

// The audience says what a token is for. One-time tokens and login states
// are signed with the same key, and the audience is what keeps them
// apart: neither can ever be used in place of the other.
const (
	audienceCertificate = "certificate"
	audienceLogin       = "login"
)

// ErrInvalid is returned by Verify for every token that is not acceptable:
// wrong signature, expired, damaged. The wrapped error has the detail.
var ErrInvalid = errors.New("invalid token")

// Grant is what a token allows its holder to request.
type Grant struct {
	// ID is unique for each token. The server remembers the IDs it has
	// seen, which is what makes a token one-time.
	ID string
	// Subject says who the token was made for, e.g. "alice@example.com".
	// It is for the logs: it gives no permission to anything.
	Subject string
	// CreatedBy is the name of the person who got the token by
	// logging in. It is empty for tokens made on the CA machine with
	// "bxp token". Like Subject, it is for the logs.
	CreatedBy string
	// KeyFingerprint, if set, ties the token to one key: it only works
	// for a certificate for the public key with this fingerprint.
	KeyFingerprint string
	// Template is the certificate template, e.g. "tls-server".
	Template string
	// Names are the names the certificate may contain: DNS names,
	// IP addresses, email addresses.
	Names []string
	// Expires is when the token stops being valid.
	Expires time.Time
}

// Verifier creates and checks tokens. Create one with New.
// It is safe for concurrent use.
type Verifier struct {
	key *ecdsa.PrivateKey
	// deriveKey is the key for Derive. It comes from the token key, so
	// it needs no file of its own and survives restarts.
	deriveKey []byte

	// now returns the current time. Tests replace it.
	now func() time.Time
}

// New returns a Verifier that signs and checks tokens with key.
func New(key *ecdsa.PrivateKey) *Verifier {
	sum := sha256.Sum256(append([]byte("bastionxp-ca derive\x00"), key.D.Bytes()...))
	return &Verifier{key: key, deriveKey: sum[:], now: time.Now}
}

// grantClaims are the token fields that are specific to BastionXP CA.
// The standard fields (issuer, expiry, ID) are in jwt.Claims.
type grantClaims struct {
	Template       string   `json:"profile"`
	Names          []string `json:"names"`
	CreatedBy      string   `json:"created_by,omitempty"`
	KeyFingerprint string   `json:"key,omitempty"`
}

// Options describe the token to create.
type Options struct {
	// Subject says who the token is for, e.g. "alice@example.com".
	// Empty means the first of Names.
	Subject string
	// Template is the certificate template, e.g. "tls-server".
	Template string
	// Names are the names the certificate may contain.
	Names []string
	// ValidFor is how long the token can be used.
	// Zero means DefaultValidity.
	ValidFor time.Duration
	// CreatedBy is the name of the person getting the token by
	// logging in. Leave it empty on the CA machine.
	CreatedBy string
	// KeyFingerprint, if set, ties the token to the key with this
	// fingerprint.
	KeyFingerprint string
}

// maxSubjectLength keeps the subject short enough for a log line.
const maxSubjectLength = 200

// Issue creates a token for one certificate.
func (v *Verifier) Issue(opts Options) (string, error) {
	if opts.Template == "" {
		return "", errors.New("a profile is required")
	}
	if len(opts.Names) == 0 {
		return "", errors.New("at least one name is required")
	}
	for _, name := range opts.Names {
		if name == "" {
			return "", errors.New("empty name")
		}
	}

	subject := opts.Subject
	if subject == "" {
		subject = opts.Names[0]
	}
	if err := checkSubject(subject); err != nil {
		return "", err
	}

	validFor := opts.ValidFor
	switch {
	case validFor == 0:
		validFor = DefaultValidity
	case validFor < 0:
		return "", fmt.Errorf("validity must be positive, got %s", validFor)
	case validFor > MaxValidity:
		return "", fmt.Errorf("validity %s is above the maximum of %s", validFor, MaxValidity)
	}

	id, err := newID()
	if err != nil {
		return "", err
	}

	now := v.now()
	standard := jwt.Claims{
		Issuer:   issuer,
		Audience: jwt.Audience{audienceCertificate},
		Subject:  subject,
		ID:       id,
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(validFor)),
	}
	return v.sign(standard, grantClaims{
		Template:       opts.Template,
		Names:          opts.Names,
		CreatedBy:      opts.CreatedBy,
		KeyFingerprint: opts.KeyFingerprint,
	})
}

// sign returns a JWT with the given claims, signed with the token key.
func (v *Verifier) sign(claims ...any) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: v.key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", err
	}
	builder := jwt.Signed(signer)
	for _, c := range claims {
		builder = builder.Claims(c)
	}
	return builder.Serialize()
}

// parse checks a JWT's signature, issuer, audience and expiry time, and
// fills in the claims. Every failure is reported as ErrInvalid.
func (v *Verifier) parse(token, audience string, standard *jwt.Claims, custom any) error {
	// Accept only the algorithm we sign with. This is what stops the
	// classic JWT attacks of switching to "none" or to a symmetric key.
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := parsed.Claims(&v.key.PublicKey, standard, custom); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}

	// No leeway: the same machine creates and checks the tokens, so
	// there is no clock difference to allow for.
	expected := jwt.Expected{
		Issuer:      issuer,
		AnyAudience: jwt.Audience{audience},
		Time:        v.now(),
	}
	if err := standard.ValidateWithLeeway(expected, 0); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	// Validate accepts a token without an expiry time. We never make
	// one, and one must never slip through as "valid forever".
	if standard.Expiry == nil {
		return fmt.Errorf("%w: no expiry time", ErrInvalid)
	}
	return nil
}

// Verify checks the token's signature and expiry time and returns what it
// allows. Every failure is reported as ErrInvalid.
//
// Verify does not know whether the token was used before. The caller must
// check that with the returned Grant.ID.
func (v *Verifier) Verify(token string) (*Grant, error) {
	var standard jwt.Claims
	var grant grantClaims
	if err := v.parse(token, audienceCertificate, &standard, &grant); err != nil {
		return nil, err
	}

	// We always set these when issuing. Check anyway, so a token missing
	// one of them can never slip through as "reusable" or "for any name".
	if standard.ID == "" || grant.Template == "" || len(grant.Names) == 0 {
		return nil, fmt.Errorf("%w: a required field is missing", ErrInvalid)
	}
	if err := checkSubject(standard.Subject); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}

	return &Grant{
		ID:             standard.ID,
		Subject:        standard.Subject,
		CreatedBy:      grant.CreatedBy,
		KeyFingerprint: grant.KeyFingerprint,
		Template:       grant.Template,
		Names:          grant.Names,
		Expires:        standard.Expiry.Time(),
	}, nil
}

// checkSubject rejects subjects that would make a mess of a log line.
// The subject ends up in the CA's log and, for SSH certificates, in the
// log of every SSH server the certificate is used on.
func checkSubject(subject string) error {
	if subject == "" {
		return errors.New("the subject is empty")
	}
	if len(subject) > maxSubjectLength {
		return fmt.Errorf("the subject is longer than %d characters", maxSubjectLength)
	}
	for _, r := range subject {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return errors.New("the subject must not contain spaces, line breaks or control characters")
		}
	}
	return nil
}

// LoadOrCreateKey reads the token signing key from dir. If there is none
// yet, it creates one.
//
// It is safe when two programs do this at the same moment, for example
// "bxp serve" starting while "bxp token" runs: both end up with the
// same key.
//
// passphrase opens the key if it is encrypted, and encrypts a new one; nil
// for none.
func LoadOrCreateKey(dir string, passphrase []byte) (*ecdsa.PrivateKey, error) {
	path := filepath.Join(dir, KeyFile)

	key, err := readKey(path, passphrase)
	if !errors.Is(err, os.ErrNotExist) {
		return key, err
	}

	if err := createKey(dir, path, passphrase); err != nil {
		return nil, fmt.Errorf("create token key: %w", err)
	}
	// Read the file back instead of using the key just made: if another
	// program created the file first, its key is the one that counts.
	return readKey(path, passphrase)
}

func readKey(path string, passphrase []byte) (*ecdsa.PrivateKey, error) {
	signer, err := keyfile.Read(path, passphrase)
	if err != nil {
		return nil, err
	}
	key, ok := signer.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s: the token key must be an ECDSA P-256 key", path)
	}
	return key, nil
}

// createKey makes a new P-256 key and saves it at path as PKCS#8 PEM,
// encrypted if a passphrase is given,
// readable only by the owner. If the file exists by then, it is left
// alone and that is not an error.
func createKey(dir, path string, passphrase []byte) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	data, err := keyfile.Marshal(key, passphrase)
	if err != nil {
		return err
	}

	// Write the whole key to a temporary file first and then give it its
	// real name in one step. This way nobody can ever read a half-written
	// key file. CreateTemp makes the file readable only by the owner.
	tmp, err := os.CreateTemp(dir, KeyFile+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Link, unlike Rename, fails if the name is taken. So the first
	// program to get here wins and a later one keeps the winner's key.
	err = os.Link(tmp.Name(), path)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	return err
}

// newID returns a random 128-bit token ID as hex.
func newID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}
