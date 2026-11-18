// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package catest has a stand-in for a company's existing PKI, for tests
// of BastionXP CA under another root: a root and an issuing CA below it, which
// sign BastionXP CA's CSR the way Active Directory Certificate Services does
// with its "Subordinate Certification Authority" template.
package catest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// Corp is a company PKI: Root -> Issuing.
type Corp struct {
	Root, Issuing       *x509.Certificate
	rootKey, issuingKey *ecdsa.PrivateKey
}

// NewCorp makes a company PKI.
func NewCorp(t testing.TB) *Corp {
	t.Helper()
	c := &Corp{rootKey: newKey(t), issuingKey: newKey(t)}
	c.Root = sign(t, &x509.Certificate{
		Subject: pkix.Name{Organization: []string{"Corp"}, CommonName: "Corp Root CA"},
		IsCA:    true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil, &c.rootKey.PublicKey, c.rootKey)
	c.Issuing = sign(t, &x509.Certificate{
		Subject: pkix.Name{Organization: []string{"Corp"}, CommonName: "Corp Issuing CA"},
		IsCA:    true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, c.Root, &c.issuingKey.PublicKey, c.rootKey)
	return c
}

// SubCAOptions change how a CSR is signed, to break one rule at a time.
type SubCAOptions struct {
	NotCA          bool
	NoCRLSign      bool
	ByRoot         bool // signed by the root directly, not the issuing CA
	PermittedNames []string
}

// SignSubCA signs a CSR (PEM) as a subordinate CA.
func (c *Corp) SignSubCA(t testing.TB, csrPEM []byte, opts SubCAOptions) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("no PEM CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		Subject:               csr.Subject,
		IsCA:                  !opts.NotCA,
		BasicConstraintsValid: true,
		MaxPathLenZero:        !opts.NotCA,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		PermittedDNSDomains:   opts.PermittedNames,
	}
	if opts.NoCRLSign {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	}
	parent, key := c.Issuing, c.issuingKey
	if opts.ByRoot {
		parent, key = c.Root, c.rootKey
	}
	return sign(t, template, parent, csr.PublicKey, key)
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

var serial int64

func sign(t testing.TB, template, parent *x509.Certificate, pub any, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	serial++
	template.SerialNumber = big.NewInt(time.Now().UnixNano() + serial)
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(2 * 365 * 24 * time.Hour)
	if parent == nil {
		parent = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
