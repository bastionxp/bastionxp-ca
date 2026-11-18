// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// A fingerprint is a short text that identifies a public key, for example
// "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8". Two keys with the
// same fingerprint are the same key.
//
// Fingerprints are used to tie a one-time token to one key: the token
// then only works for a certificate for that key, so it is of no use to
// anybody who does not hold the matching private key.

// SSHFingerprint returns the fingerprint of an SSH public key. It is the
// same text that "ssh-keygen -l" prints.
func SSHFingerprint(pub ssh.PublicKey) string {
	return ssh.FingerprintSHA256(pub)
}

// X509Fingerprint returns the fingerprint of the public key in a CSR or
// a certificate.
func X509Fingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("fingerprint of public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// CertFingerprint returns the SHA-256 fingerprint of a whole certificate,
// as lower-case hex: the text "bxp init" prints for the root and that
// clients check with "bxp trust".
func CertFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}
