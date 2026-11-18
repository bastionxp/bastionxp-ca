// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package scep is a SCEP server and client (RFC 8894). SCEP is the
// protocol that phones, laptops under device management (MDM), routers
// and printers use to get a certificate.
//
// How a device gets a certificate:
//
//  1. It asks the server for its certificates (GetCACert).
//  2. It makes a key and a CSR. The CSR contains a "challenge password",
//     which proves that the device may have a certificate. For BastionXP CA the
//     challenge is a one-time token, the same kind "bxp token" makes.
//  3. It encrypts the CSR for the server, signs the result with its new
//     key, and sends it (PKIOperation).
//  4. The server decrypts the CSR, checks the challenge, has the CA sign
//     the certificate, and sends it back, encrypted for the device.
//
// SCEP messages are packed in PKCS#7 (also called CMS): a format for
// signed and for encrypted data. The encryption only works with RSA keys.
// So the server has its own RSA key and certificate for SCEP, called the
// RA ("registration authority", see ra.go), and devices must use RSA
// keys too.
//
// The files of this package:
//
//	scep.go     constants, and the one setting of the PKCS#7 library
//	server.go   the HTTP side of the server
//	message.go  reads requests and builds answers
//	ra.go       the server's own RSA key and certificate
//	csr.go      puts a challenge into a CSR and gets it out again
//	client.go   the client
//
// Besides enrollment (PKCSReq), the server handles renewal with the
// current certificate (RenewalReq) and GetCert, when it is given the
// functions that decide them. What is not here: GetCRL (the CRL is at
// /crl) and polling (every answer is immediate).
package scep

import (
	"encoding/asn1"

	"go.mozilla.org/pkcs7"
)

// Path is where the SCEP server lives. A device is configured with the
// CA's address followed by this path.
const Path = "/scep"

// The attributes of a SCEP message. They travel in the signed part.
var (
	oidMessageType    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidPKIStatus      = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	oidFailInfo       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}
	oidSenderNonce    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidRecipientNonce = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
	oidTransactionID  = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
)

// Message types. SCEP writes these numbers as text.
const (
	messagePKCSReq    = "19" // a device asks for a certificate
	messageRenewalReq = "17" // a device asks for a new one, signed with its current one
	messageGetCert    = "21" // a device asks for a certificate it got before
	messageCertRep    = "3"  // the server's answer
)

// What the server's answer says.
const (
	statusSuccess = "0"
	statusFailure = "2"
)

// Why a request failed. SCEP has only a few reasons to choose from, and
// none of them says much: the real reason goes to the server's log.
const (
	failBadAlgorithm    = "0" // an algorithm the server cannot use
	failBadMessageCheck = "1" // the signature is wrong
	failBadRequest      = "2" // not allowed, or not understood
	failBadCertID       = "4" // no such certificate
)

// capabilities is the answer to GetCACaps: what this server can do.
//
//	POSTPKIOperation  requests may be sent with HTTP POST
//	SHA-256, AES      the modern algorithms are understood
//	SCEPStandard      the server follows RFC 8894
//	Renewal           a device can renew with its current certificate
//	                  (only if the server was given a RenewFunc)
const capabilities = "POSTPKIOperation\nSHA-256\nAES\nSCEPStandard\n"

func init() {
	// The PKCS#7 library encrypts with DES unless told otherwise, and it
	// is told through this variable of its own. DES has been broken for
	// decades. Everything this package encrypts uses AES-256.
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256CBC
}
