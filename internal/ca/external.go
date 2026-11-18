// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/keyfile"
)

// BastionXP CA under an existing root: a company that already has a root on
// every machine (Active Directory Certificate Services, another CA) has
// that root sign BastionXP CA's intermediate, instead of trusting a new root.
//
//  1. InitExternal makes the intermediate key and a CSR for it, and the
//     other keys. There is no root key here.
//  2. The company's CA signs the CSR.
//  3. ImportIntermediate checks the certificate and puts it in place,
//     with the root and, if any, the CAs between them.
//
// Replacing the intermediate later is the same: NewIntermediateCSR, then
// ImportIntermediate. BastionXP CA still has exactly one intermediate of its
// own; the CAs above it only travel along, so clients can build the chain.

// Files of the external mode.
const (
	// ChainFile holds the CAs between the intermediate and the root,
	// e.g. the company's issuing CA. Missing when there are none.
	ChainFile = "chain.crt"
	// The next intermediate's key and CSR, until its certificate is
	// imported.
	NextIntermediateKeyFile = "intermediate.next.key"
	NextIntermediateCSRFile = "intermediate.next.csr"
)

// ErrWaitingForIntermediate is returned by Load for a CA made with
// InitExternal whose intermediate certificate is not imported yet.
var ErrWaitingForIntermediate = errors.New("the intermediate certificate has not been imported yet")

// Chain returns the certificates that go with every certificate the CA
// issues: the intermediate, then the CAs above it up to (not including)
// the root.
func (c *CA) Chain() []*x509.Certificate {
	return append([]*x509.Certificate{c.intermediateCert}, c.chain...)
}

// IntermediateCSROptions are the settings of the intermediate's CSR.
type IntermediateCSROptions struct {
	Name, Organization, KeyType string
	// KeyPassphrase encrypts the key, like the server's other keys.
	KeyPassphrase []byte
}

// NewIntermediateCSR makes the next intermediate key and a CSR for it, for
// another CA to sign, and returns the CSR in PEM form.
func NewIntermediateCSR(dir string, opts IntermediateCSROptions) ([]byte, error) {
	keyFile := filepath.Join(dir, NextIntermediateKeyFile)
	if _, err := os.Stat(keyFile); err == nil {
		return nil, fmt.Errorf("%s exists already: import its certificate first, or remove it to start over", keyFile)
	}
	key, err := generateKey(opts.KeyType)
	if err != nil {
		return nil, err
	}
	// Ask for what an intermediate needs. The signing CA decides; Active
	// Directory's "Subordinate Certification Authority" template sets it
	// by itself.
	basic, err := asn1.Marshal(struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional"`
	}{IsCA: true, MaxPathLen: 0})
	if err != nil {
		return nil, err
	}
	usage, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x06}, BitLength: 7}) // keyCertSign, cRLSign
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{Organization: []string{opts.Organization}, CommonName: opts.Name + " Intermediate CA"},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: basic},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: usage},
		},
	}, key)
	if err != nil {
		return nil, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if err := writeKey(keyFile, key, opts.KeyPassphrase); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, NextIntermediateCSRFile), csrPEM, 0o644); err != nil {
		os.Remove(keyFile)
		return nil, err
	}
	return csrPEM, nil
}

// InitExternal creates a CA in dir whose root is another CA's: the SSH CA
// keys, and the intermediate key with its CSR. The CA works once
// ImportIntermediate has put the signed certificate in place.
func InitExternal(dir string, opts InitOptions) ([]byte, error) {
	if opts.Name == "" || opts.Organization == "" {
		return nil, errors.New("CA name and organization are required")
	}
	if err := CheckNew(dir, ""); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	csr, err := NewIntermediateCSR(dir, IntermediateCSROptions{
		Name: opts.Name, Organization: opts.Organization, KeyType: opts.KeyType, KeyPassphrase: opts.KeyPassphrase,
	})
	if err != nil {
		return nil, err
	}
	for _, ssh := range []struct{ key, pub, comment string }{
		{SSHUserCAKeyFile, SSHUserCAPubFile, opts.Name + " SSH User CA"},
		{SSHHostCAKeyFile, SSHHostCAPubFile, opts.Name + " SSH Host CA"},
	} {
		key, err := generateKey(opts.KeyType)
		if err != nil {
			return nil, err
		}
		if err := writeSSHCA(dir, ssh.key, ssh.pub, key, ssh.comment, opts.KeyPassphrase); err != nil {
			return nil, err
		}
	}
	return csr, nil
}

// ImportOptions are what ImportIntermediate takes.
type ImportOptions struct {
	// Cert is the intermediate certificate the other CA issued for the
	// CSR.
	Cert *x509.Certificate
	// Chain are the CAs between Cert and the root, if any.
	Chain []*x509.Certificate
	// Root is the root certificate. Needed the first time; afterwards
	// the CA's root.crt, and a different one is refused.
	Root *x509.Certificate
	// KeyPassphrase opens the next intermediate key.
	KeyPassphrase []byte
}

// ImportIntermediate checks a signed intermediate certificate for the next
// key and puts it in place. A replaced intermediate's certificate is kept
// in data_dir/replaced; its key is removed.
func ImportIntermediate(dir string, opts ImportOptions) error {
	cert := opts.Cert
	if cert == nil {
		return errors.New("no certificate to import")
	}
	key, err := keyfile.Read(filepath.Join(dir, NextIntermediateKeyFile), opts.KeyPassphrase)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("there is no CSR waiting for a certificate: make one with bxp new-intermediate --csr")
	}
	if err != nil {
		return err
	}
	if !keyMatches(key, cert.PublicKey) {
		return errors.New("the certificate is not for the key of the waiting CSR")
	}

	// The root: the one the CA has, or the one given the first time.
	root := opts.Root
	existing, err := readCert(filepath.Join(dir, RootCertFile))
	switch {
	case err == nil && root != nil && !existing.Equal(root):
		return errors.New("this is not the CA's root certificate: the root cannot change")
	case err == nil:
		root = existing
	case root == nil:
		return errors.New("give the root certificate the first time")
	}
	if !root.IsCA || root.CheckSignatureFrom(root) != nil {
		return errors.New("the root certificate is not a self-signed CA certificate")
	}

	// What an intermediate of BastionXP CA must be able to do.
	switch {
	case !cert.BasicConstraintsValid || !cert.IsCA:
		return errors.New("the certificate is not a CA certificate: ask for a subordinate CA (in Active Directory: the \"Subordinate Certification Authority\" template)")
	case cert.KeyUsage&x509.KeyUsageCertSign == 0:
		return errors.New("the certificate may not sign certificates (key usage keyCertSign)")
	case cert.KeyUsage&x509.KeyUsageCRLSign == 0:
		return errors.New("the certificate may not sign CRLs (key usage cRLSign), which BastionXP CA does for revocation")
	}
	// It chains up to the root, through the given CAs, with every limit
	// on the way respected, and is valid now.
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	for _, c := range opts.Chain {
		intermediates.AddCert(c)
	}
	chains, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
		CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return fmt.Errorf("the certificate does not chain up to the root: %w", err)
	}
	// The CAs in between, in order from the intermediate's issuer up,
	// and only those on the way.
	between := chains[0][1 : len(chains[0])-1]

	// Put it in place. root.crt comes last: it marks the CA as ready.
	certFile := filepath.Join(dir, IntermediateCertFile)
	if old, err := readCert(certFile); err == nil {
		if err := os.MkdirAll(filepath.Join(dir, ReplacedDir), 0o700); err != nil {
			return err
		}
		record := filepath.Join(dir, ReplacedDir, time.Now().UTC().Format("20060102-150405")+"-"+IntermediateCertFile)
		if err := writeCert(record, old); err != nil {
			return err
		}
	}
	if err := writeFileReplacing(certFile, EncodeCertPEM(cert), 0o644); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(dir, NextIntermediateKeyFile), filepath.Join(dir, IntermediateKeyFile)); err != nil {
		return fmt.Errorf("the certificate is in place but its key is not (%w): move %s to %s by hand",
			err, NextIntermediateKeyFile, IntermediateKeyFile)
	}
	os.Remove(filepath.Join(dir, NextIntermediateCSRFile))
	chainFile := filepath.Join(dir, ChainFile)
	if len(between) > 0 {
		if err := writeFileReplacing(chainFile, EncodeCertPEM(between...), 0o644); err != nil {
			return err
		}
	} else {
		os.Remove(chainFile)
	}
	if _, err := os.Stat(filepath.Join(dir, RootCertFile)); err != nil {
		return writeCert(filepath.Join(dir, RootCertFile), root)
	}
	return nil
}

// ParseCerts reads every PEM certificate in data.
func ParseCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no PEM certificate found")
	}
	return certs, nil
}

func readCerts(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	certs, err := ParseCerts(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return certs, nil
}

// writeFileReplacing writes data to path through a temporary file, so
// that nobody ever reads half a file.
func writeFileReplacing(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// verifiesUpTo checks that cert is signed by the root, directly or through
// chain. It does not look at the time: an expired intermediate still
// loads, and the server warns about it.
func verifiesUpTo(cert *x509.Certificate, chain []*x509.Certificate, root *x509.Certificate) error {
	if len(chain) == 0 {
		return cert.CheckSignatureFrom(root)
	}
	parent := root
	for i := len(chain) - 1; i >= 0; i-- {
		if err := chain[i].CheckSignatureFrom(parent); err != nil {
			return err
		}
		parent = chain[i]
	}
	return cert.CheckSignatureFrom(parent)
}
