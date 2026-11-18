// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"bytes"
	"cmp"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// BastionXP CA has exactly one intermediate at any time. ReplaceIntermediate
// swaps it for a new one, signed by the root, for when the old one is
// about to expire or its key may be in the wrong hands.
//
// The old key is removed: nothing can use it any more. Its certificate is
// kept in data_dir/replaced for the record, and never loaded. Certificates
// the old intermediate issued stay valid (same root), but the CA can no
// longer say whether they are revoked: the CRL and the OCSP answers come
// from the new intermediate from then on. Renewing them moves them over.

// ReplacedDir is the directory below data_dir with the certificates of
// replaced intermediates.
const ReplacedDir = "replaced"

// ReplaceOptions are the settings for ReplaceIntermediate.
type ReplaceOptions struct {
	Name         string // as at Init
	Organization string // as at Init
	KeyType      string // KeyTypeECDSA or KeyTypeRSA
	// RootKey is the root's private key, from offline storage.
	RootKey crypto.Signer
	// KeyPassphrase encrypts the new key: the passphrase of the server's
	// other keys, or empty if they are not encrypted.
	KeyPassphrase []byte
	// NameConstraints for the new intermediate; see constraints.go.
	NameConstraints NameConstraints
	// Validity is the new intermediate's lifetime. Zero: 3 years.
	Validity time.Duration
}

// ErrOutlivesRoot is returned by ReplaceIntermediate when the new
// intermediate would be valid for longer than the root.
var ErrOutlivesRoot = errors.New("the new intermediate would outlive the root")

// IssuedBy reports whether cert was signed by the intermediate
// certificate issuer, by its key identifier.
func IssuedBy(cert, issuer *x509.Certificate) bool {
	return len(cert.AuthorityKeyId) > 0 && bytes.Equal(cert.AuthorityKeyId, issuer.SubjectKeyId)
}

// ReplaceIntermediate makes a new intermediate in dir, signed by the root,
// in place of the current one, and returns it. The server uses it after a
// restart.
func ReplaceIntermediate(dir string, opts ReplaceOptions) (*x509.Certificate, error) {
	root, err := readCert(filepath.Join(dir, RootCertFile))
	if err != nil {
		return nil, fmt.Errorf("load root certificate: %w", err)
	}
	if opts.RootKey == nil || !keyMatches(opts.RootKey, root.PublicKey) {
		return nil, errors.New("this is not the key of this CA's root certificate")
	}
	old, err := readCert(filepath.Join(dir, IntermediateCertFile))
	if err != nil {
		return nil, fmt.Errorf("load intermediate certificate: %w", err)
	}

	now := time.Now()
	key, err := generateKey(opts.KeyType)
	if err != nil {
		return nil, fmt.Errorf("generate intermediate key: %w", err)
	}
	validity := cmp.Or(opts.Validity, defaultIntermediateValidity)
	template, err := caTemplate(InitOptions{Name: opts.Name, Organization: opts.Organization}, "Intermediate CA", now, validity)
	if err != nil {
		return nil, err
	}
	// Never beyond the root: a chain is only valid while all of it is.
	// Say so rather than make it shorter than asked: the root's end needs
	// a plan of its own.
	if template.NotAfter.After(root.NotAfter) {
		days := int(root.NotAfter.Sub(now).Hours() / 24)
		return nil, fmt.Errorf("%w: the root ends on %s, in %d days. Set ca.intermediate_validity to at most %dd, and plan a new root",
			ErrOutlivesRoot, root.NotAfter.Format(time.DateOnly), days, days)
	}
	template.MaxPathLenZero = true
	opts.NameConstraints.apply(template)
	cert, err := signCert(template, root, key.Public(), opts.RootKey)
	if err != nil {
		return nil, fmt.Errorf("create intermediate certificate: %w", err)
	}

	// Write the new files beside the old ones, keep a copy of the old
	// certificate, and only then put the new files in place.
	keyFile := filepath.Join(dir, IntermediateKeyFile)
	certFile := filepath.Join(dir, IntermediateCertFile)
	keepNew := false // set when the new files must stay for a fix by hand
	defer func() {
		if !keepNew {
			os.Remove(keyFile + ".new")
			os.Remove(certFile + ".new")
		}
	}()
	if err := writeKey(keyFile+".new", key, opts.KeyPassphrase); err != nil {
		return nil, err
	}
	if err := writeCert(certFile+".new", cert); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Join(dir, ReplacedDir), 0o700); err != nil {
		return nil, err
	}
	record := filepath.Join(dir, ReplacedDir, now.UTC().Format("20060102-150405")+"-"+IntermediateCertFile)
	if err := writeCert(record, old); err != nil {
		return nil, err
	}

	// Renaming over the old key removes it.
	if err := os.Rename(keyFile+".new", keyFile); err != nil {
		return nil, err
	}
	if err := os.Rename(certFile+".new", certFile); err != nil {
		keepNew = true
		return nil, fmt.Errorf("the new intermediate key is in place but its certificate is not (%w): "+
			"move %s.new to %s by hand", err, certFile, certFile)
	}
	return cert, nil
}

// loadReplacedIntermediates reads the certificates of the intermediates
// that were replaced, kept in ReplacedDir.
func (c *CA) loadReplacedIntermediates(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, ReplacedDir, "*-"+IntermediateCertFile))
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, file := range files {
		cert, err := readCert(file)
		if err != nil {
			return fmt.Errorf("replaced intermediate: %w", err)
		}
		c.replacedIntermediates = append(c.replacedIntermediates, cert)
	}
	return nil
}

// ReplacedIntermediates returns the intermediates that were replaced. The
// certificates they issued stay valid, and are renewed onto the current
// intermediate: the server accepts them as proof for a renewal. That is
// safe even if a replaced intermediate's key was stolen, because a
// renewal also needs the very certificate in the CA's list.
func (c *CA) ReplacedIntermediates() []*x509.Certificate {
	return c.replacedIntermediates
}
