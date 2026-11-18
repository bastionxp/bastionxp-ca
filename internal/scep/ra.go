// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package scep

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
)

// File names of the RA inside the CA data directory.
const (
	RAKeyFile  = "scep_ra.key"
	RACertFile = "scep_ra.crt"
)

const (
	raKeyBits = 3072
	// raValidity is how long an RA certificate is valid.
	raValidity = 365 * 24 * time.Hour
	// raRenewBefore is how long before its end the RA certificate is
	// replaced, at the next start of the server.
	raRenewBefore = 30 * 24 * time.Hour
)

// raTemplate describes the RA certificate. It has no special purpose
// marked in it: it signs and decrypts SCEP messages, nothing else.
var raTemplate = ca.X509Template{
	Name:            "scep-ra",
	DefaultValidity: raValidity,
	MaxValidity:     raValidity,
}

// RA is the SCEP server's own key and certificate.
//
// Devices encrypt their requests for the server, and with SCEP that
// takes an RSA key. The CA's own keys are ECDSA by default, and should
// not be used for decrypting anyway. So the SCEP server gets a separate
// RSA key with a certificate from the CA. Devices learn it with
// GetCACert before every enrollment, so it can be replaced at any time.
type RA struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

// LoadOrCreateRA reads the RA from dir. If there is none, or its
// certificate ends soon, it makes a new key and has the CA issue a
// certificate for it.
func LoadOrCreateRA(dir string, authority *ca.CA) (*RA, error) {
	ra, err := loadRA(dir)
	if err == nil && time.Until(ra.Cert.NotAfter) > raRenewBefore {
		return ra, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("load SCEP RA: %w", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, raKeyBits)
	if err != nil {
		return nil, fmt.Errorf("create SCEP RA key: %w", err)
	}
	cert, err := authority.IssueX509(ca.X509Request{
		Template:   raTemplate,
		PublicKey:  key.Public(),
		CommonName: "SCEP RA",
	})
	if err != nil {
		return nil, fmt.Errorf("create SCEP RA certificate: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	// The key first: a key without its certificate is noticed and
	// replaced at the next start, a certificate without its key is too.
	if err := writeFile(filepath.Join(dir, RAKeyFile), keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("save SCEP RA key: %w", err)
	}
	if err := writeFile(filepath.Join(dir, RACertFile), ca.EncodeCertPEM(cert), 0o644); err != nil {
		return nil, fmt.Errorf("save SCEP RA certificate: %w", err)
	}
	return &RA{Cert: cert, Key: key}, nil
}

func loadRA(dir string) (*RA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, RACertFile))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, RAKeyFile))
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, errors.New("the SCEP RA files are damaged: delete scep_ra.key and scep_ra.crt and start again")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("the SCEP RA key does not match its certificate: delete scep_ra.key and scep_ra.crt and start again")
	}
	return &RA{Cert: cert, Key: key}, nil
}

// writeFile replaces a file with the given content and mode.
func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	// WriteFile keeps the mode of a file that already exists.
	return os.Chmod(path, mode)
}
