// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/bastionxp/bastionxp-ca/internal/keyfile"
)

// Key types for the CA's own keys.
const (
	KeyTypeECDSA = "ecdsa" // P-256
	KeyTypeRSA   = "rsa"   // 3072 bit
)

const (
	rsaCAKeyBits   = 3072
	rsaMinLeafBits = 2048
)

// generateKey creates a new private key for the CA itself.
func generateKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case KeyTypeECDSA:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return key, nil
	case KeyTypeRSA:
		key, err := rsa.GenerateKey(rand.Reader, rsaCAKeyBits)
		if err != nil {
			return nil, err
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", keyType)
	}
}

// checkPublicKey rejects public keys that are too weak or of a type the CA
// does not sign. It is applied to every key a certificate is requested for.
func checkPublicKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		}
		return errors.New("unsupported ECDSA curve (use P-256, P-384 or P-521)")
	case *rsa.PublicKey:
		if k.N.BitLen() < rsaMinLeafBits {
			return fmt.Errorf("RSA key is %d bits, minimum is %d", k.N.BitLen(), rsaMinLeafBits)
		}
		return nil
	case ed25519.PublicKey:
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
}

// newSerial returns a random, positive 159-bit certificate serial number.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 159)
	for {
		serial, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
}

// writeKey saves a private key as PKCS#8 PEM, readable only by the owner.
// It refuses to overwrite an existing file.
// writeKey saves key at path as PKCS#8 PEM, readable only by the owner,
// encrypted if a passphrase is given.
func writeKey(path string, key crypto.Signer, passphrase []byte) error {
	data, err := keyfile.Marshal(key, passphrase)
	if err != nil {
		return err
	}
	return writeNewFile(path, data, 0o600)
}

func writeCert(path string, cert *x509.Certificate) error {
	return writeNewFile(path, EncodeCertPEM(cert), 0o644)
}

func readCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no PEM certificate found", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cert, nil
}

// writeNewFile creates path with the given content and fails if it exists.
func writeNewFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// EncodeCertPEM returns the certificates as concatenated PEM blocks, in the
// order given. Pass leaf first, then intermediate, to build a chain file.
func EncodeCertPEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, cert := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return out
}

// keyMatches reports whether the private key belongs to the public key.
func keyMatches(key crypto.Signer, pub crypto.PublicKey) bool {
	type equaler interface {
		Equal(crypto.PublicKey) bool
	}
	keyPub, ok := key.Public().(equaler)
	return ok && keyPub.Equal(pub)
}
