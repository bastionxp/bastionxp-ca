// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package scep

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// oidChallengePassword is the CSR attribute that carries the challenge.
var oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}

// oidSHA256WithRSA is the signature algorithm of the CSRs made here.
var oidSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}

// The parts of a CSR, as far as this file needs them. Go's x509 package
// can neither write nor read the challenge attribute, so the two
// functions below take a CSR apart themselves.
type csrASN1 struct {
	Info               csrInfoASN1
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
}

type csrInfoASN1 struct {
	Raw        asn1.RawContent
	Version    int
	Subject    asn1.RawValue
	PublicKey  asn1.RawValue
	Attributes []asn1.RawValue `asn1:"tag:0"`
}

type attributeASN1 struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue // a SET
}

// NewCSR creates a CSR like x509.CreateCertificateRequest does, and adds
// the challenge to it. It returns the CSR in DER form.
//
// The key must be an RSA key: a SCEP server sends the certificate back
// encrypted, and that only works with RSA.
func NewCSR(template *x509.CertificateRequest, key *rsa.PrivateKey, challenge string) ([]byte, error) {
	if challenge == "" {
		return nil, errors.New("a challenge is required")
	}
	// Let the standard library do everything it can do.
	plain, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, err
	}
	var csr csrASN1
	if _, err := asn1.Unmarshal(plain, &csr); err != nil {
		return nil, err
	}

	// Add the attribute: the type, and a set with the one value. The
	// value is a UTF8String. The older PrintableString cannot hold the
	// "_" that a token may contain.
	value, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte(challenge)})
	if err != nil {
		return nil, err
	}
	attribute, err := asn1.Marshal(attributeASN1{
		Type:   oidChallengePassword,
		Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: value},
	})
	if err != nil {
		return nil, err
	}
	csr.Info.Attributes = append(csr.Info.Attributes, asn1.RawValue{FullBytes: attribute})

	// The signature covered the old content, so sign again.
	csr.Info.Raw = nil // marshal from the fields, not from the old bytes
	info, err := asn1.Marshal(csr.Info)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(info)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(csrASN1{
		Info:               csrInfoASN1{Raw: info},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256WithRSA, Parameters: asn1.NullRawValue},
		Signature:          asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

// Challenge returns the challenge of a CSR in DER form, or "" if it has
// none.
func Challenge(csrDER []byte) string {
	var csr csrASN1
	if _, err := asn1.Unmarshal(csrDER, &csr); err != nil {
		return ""
	}
	for _, raw := range csr.Info.Attributes {
		var attribute attributeASN1
		if _, err := asn1.Unmarshal(raw.FullBytes, &attribute); err != nil {
			continue
		}
		if !attribute.Type.Equal(oidChallengePassword) {
			continue
		}
		// The set holds one string. Devices write it as one of several
		// string types; the text is in the bytes in every case.
		var value asn1.RawValue
		if _, err := asn1.Unmarshal(attribute.Values.Bytes, &value); err != nil {
			return ""
		}
		switch value.Tag {
		case asn1.TagUTF8String, asn1.TagPrintableString, asn1.TagIA5String, asn1.TagT61String:
			return string(value.Bytes)
		}
		return ""
	}
	return ""
}
