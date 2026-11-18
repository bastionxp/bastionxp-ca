// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

// This file lets the CA say which of its certificates are no longer to
// be trusted. There are two ways to say it, and the CA signs both with
// the intermediate key, the key that signed the certificates:
//
//   - a CRL (certificate revocation list): one signed list of all revoked
//     certificates, which others download from time to time;
//   - an OCSP answer: a signed answer to "what about this one?".
//
// Which certificates are revoked is not known here. The caller looks
// that up; this package only signs what it is told.

// Reasons for revoking a certificate (RFC 5280). They are written into
// the CRL and the OCSP answers.
const (
	ReasonUnspecified          = 0
	ReasonKeyCompromise        = 1 // the private key may be in the wrong hands
	ReasonSuperseded           = 4 // replaced by a new certificate
	ReasonCessationOfOperation = 5 // no longer needed
)

const (
	// crlValidity is how long others may keep using a CRL before they
	// fetch a new one.
	crlValidity = 24 * time.Hour
	// ocspValidity is the same for an OCSP answer. It is short, so
	// that a revocation is seen soon.
	ocspValidity = time.Hour
)

// Revoked is one revoked certificate.
type Revoked struct {
	Serial    *big.Int
	RevokedAt time.Time
	Reason    int
}

// SignCRL returns a signed list of the revoked certificates, in DER form.
func (c *CA) SignCRL(revoked []Revoked) ([]byte, error) {
	now := c.now()
	template := &x509.RevocationList{
		// Every CRL needs a number higher than the one before. The
		// time is good enough for that.
		Number:     big.NewInt(now.Unix()),
		ThisUpdate: now.Add(-backdate),
		NextUpdate: now.Add(crlValidity),
	}
	for _, r := range revoked {
		template.RevokedCertificateEntries = append(template.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   r.Serial,
			RevocationTime: r.RevokedAt,
			ReasonCode:     r.Reason,
		})
	}
	return x509.CreateRevocationList(rand.Reader, template, c.intermediateCert, c.intermediateKey)
}

// OCSPStatus is what the CA knows about one certificate.
type OCSPStatus struct {
	// Known is false for a serial number the CA has no record of.
	Known bool
	// Revoked, RevokedAt and Reason describe a revoked certificate.
	Revoked   bool
	RevokedAt time.Time
	Reason    int
}

// IssuedByThisCA reports whether an OCSP request asks about a certificate
// of this CA. A request does not name the CA; it carries hashes of the
// CA's name and key.
func (c *CA) IssuedByThisCA(req *ocsp.Request) bool {
	if !req.HashAlgorithm.Available() {
		return false
	}
	// The key hash is over the key bits alone, without the wrapping
	// that says what kind of key it is.
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.intermediateCert.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return false
	}
	return bytes.Equal(hashWith(req.HashAlgorithm, publicKeyInfo.PublicKey.RightAlign()), req.IssuerKeyHash) &&
		bytes.Equal(hashWith(req.HashAlgorithm, c.intermediateCert.RawSubject), req.IssuerNameHash)
}

func hashWith(algorithm crypto.Hash, data []byte) []byte {
	h := algorithm.New()
	h.Write(data)
	return h.Sum(nil)
}

// SignOCSP returns a signed answer about the certificate with the given
// serial number, in DER form.
func (c *CA) SignOCSP(serial *big.Int, status OCSPStatus) ([]byte, error) {
	now := c.now()
	template := ocsp.Response{
		SerialNumber: serial,
		ThisUpdate:   now.Add(-backdate),
		NextUpdate:   now.Add(ocspValidity),
	}
	switch {
	case !status.Known:
		// Not "good": a certificate we never issued must not pass as
		// one of ours just because it is not on the revoked list.
		template.Status = ocsp.Unknown
	case status.Revoked:
		template.Status = ocsp.Revoked
		template.RevokedAt = status.RevokedAt
		template.RevocationReason = status.Reason
	default:
		template.Status = ocsp.Good
	}
	// The intermediate signs the answer itself, so a client needs
	// nothing but the CA's certificates to check it.
	return ocsp.CreateResponse(c.intermediateCert, c.intermediateCert, template, c.intermediateKey)
}
