// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package scep

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"go.mozilla.org/pkcs7"
)

// A SCEP message has two layers, like a letter in two envelopes:
//
//	outer: signed data    who sent it, plus the SCEP attributes
//	inner: enveloped data the content, encrypted for the receiver
//
// In a request the content is the CSR, or for GetCert the issuer and
// serial number of the certificate wanted. In an answer it is the
// certificate.

// request is a device's request after it has been opened.
type request struct {
	messageType   string
	transactionID string
	senderNonce   []byte
	// signer is the certificate the device signed the request with: one
	// it made itself, for its key, or for a renewal its current one.
	signer *x509.Certificate
	// content is the decrypted content.
	content []byte
}

// openRequest checks the signature of a request and decrypts its content
// with the RA key.
func openRequest(body []byte, ra *RA) (*request, error) {
	outer, err := pkcs7.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("not a SCEP message: %w", err)
	}
	// This proves that the sender holds the key of the certificate in
	// the message. Whether it may have a certificate is decided later,
	// by the challenge.
	if err := outer.Verify(); err != nil {
		return nil, fmt.Errorf("the signature is not valid: %w", err)
	}
	signer := outer.GetOnlySigner()
	if signer == nil {
		return nil, errors.New("the message must be signed by exactly one certificate")
	}

	req := &request{signer: signer}
	if err := outer.UnmarshalSignedAttribute(oidMessageType, &req.messageType); err != nil {
		return nil, errors.New("the message has no message type")
	}
	if err := outer.UnmarshalSignedAttribute(oidTransactionID, &req.transactionID); err != nil {
		return nil, errors.New("the message has no transaction ID")
	}
	if err := outer.UnmarshalSignedAttribute(oidSenderNonce, &req.senderNonce); err != nil {
		return nil, errors.New("the message has no sender nonce")
	}

	inner, err := pkcs7.Parse(outer.Content)
	if err != nil {
		return nil, fmt.Errorf("the content is not encrypted data: %w", err)
	}
	req.content, err = inner.Decrypt(ra.Cert, ra.Key)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt the content: %w", err)
	}
	return req, nil
}

// successReply builds the answer that carries the new certificate,
// encrypted for the device and signed by the RA.
func successReply(req *request, cert *x509.Certificate, ra *RA) ([]byte, error) {
	// The certificate travels as "degenerate" signed data: the PKCS#7
	// way of saying "here are some certificates".
	certs, err := pkcs7.DegenerateCertificate(cert.Raw)
	if err != nil {
		return nil, err
	}
	encrypted, err := pkcs7.Encrypt(certs, []*x509.Certificate{req.signer})
	if err != nil {
		return nil, err
	}
	return signReply(req, encrypted, statusSuccess, "", ra)
}

// failureReply builds the answer that says no.
func failureReply(req *request, failInfo string, ra *RA) ([]byte, error) {
	return signReply(req, nil, statusFailure, failInfo, ra)
}

func signReply(req *request, content []byte, status, failInfo string, ra *RA) ([]byte, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	attributes := []pkcs7.Attribute{
		printable(oidMessageType, messageCertRep),
		printable(oidTransactionID, req.transactionID),
		printable(oidPKIStatus, status),
		// The device's nonce comes back, so it knows the answer
		// belongs to its request.
		{Type: oidRecipientNonce, Value: req.senderNonce},
		{Type: oidSenderNonce, Value: nonce},
	}
	if failInfo != "" {
		attributes = append(attributes, printable(oidFailInfo, failInfo))
	}

	signed, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, err
	}
	signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := signed.AddSigner(ra.Cert, ra.Key, pkcs7.SignerInfoConfig{ExtraSignedAttributes: attributes}); err != nil {
		return nil, err
	}
	return signed.Finish()
}

// printable returns an attribute whose value is a short text. SCEP wants
// these as PrintableString.
func printable(oid asn1.ObjectIdentifier, text string) pkcs7.Attribute {
	return pkcs7.Attribute{
		Type:  oid,
		Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagPrintableString, Bytes: []byte(text)},
	}
}

// isRSA reports whether a certificate has an RSA key. Only then can
// something be encrypted for it.
func isRSA(cert *x509.Certificate) bool {
	_, ok := cert.PublicKey.(*rsa.PublicKey)
	return ok
}
