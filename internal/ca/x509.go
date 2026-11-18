// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"time"
)

// X509Request is everything the CA needs to issue one X.509 certificate.
//
// The CA signs exactly what is asked for. The caller must already have
// checked that the requester is allowed to have these names.
type X509Request struct {
	Template  X509Template
	PublicKey crypto.PublicKey // the key the certificate is for

	CommonName     string
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string

	// Validity is how long the certificate is valid.
	// Zero means "use the template's default".
	Validity time.Duration

	// RecordAs is the kind the certificate is recorded as, if not the
	// template's name. The server's own certificate uses OwnServerCert.
	RecordAs string

	// Protocol is how the certificate was obtained: ProtocolAPI,
	// ProtocolACME or ProtocolSCEP; empty for the CA's own certificates.
	// It is recorded, and a certificate is renewed only the way it was
	// obtained.
	Protocol string
}

// How a certificate was obtained.
const (
	ProtocolAPI  = "api"  // BastionXP CA's own API: a token or a login; renewed with "bxp renew"
	ProtocolACME = "acme" // ACME; renewed by the ACME client, with a new order
	ProtocolSCEP = "scep" // SCEP; renewed with SCEP's renewal request
)

// OwnServerCert is the kind the server's own TLS certificate is recorded
// as. It is the CA's business: it cannot be renewed through the API, and
// it is replaced at every start.
const OwnServerCert = "bastionxp-ca-server"

// RequestFromCSR builds a request from a certificate signing request.
// It checks the CSR's signature, which proves the requester holds the
// private key. The names are copied as they are: the caller still has to
// check that the requester is allowed to have them.
func RequestFromCSR(template X509Template, csr *x509.CertificateRequest) (X509Request, error) {
	if err := csr.CheckSignature(); err != nil {
		return X509Request{}, fmt.Errorf("invalid CSR signature: %w", err)
	}
	return X509Request{
		Template:       template,
		PublicKey:      csr.PublicKey,
		CommonName:     csr.Subject.CommonName,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
	}, nil
}

// IssueX509 signs a certificate with the intermediate CA key.
func (c *CA) IssueX509(req X509Request) (*x509.Certificate, error) {
	if err := checkX509Request(req); err != nil {
		return nil, fmt.Errorf("%s certificate: %w", req.Template.Name, err)
	}
	if err := checkProfile(req); err != nil {
		return nil, fmt.Errorf("%s certificate: %w", req.Template.Name, err)
	}
	validity, err := chooseValidity(req.Validity, req.Template.DefaultValidity, req.Template.MaxValidity)
	if err != nil {
		return nil, fmt.Errorf("%s certificate: %w", req.Template.Name, err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	// A certificate must not outlive the CA certificate that signed it.
	now := c.now()
	notAfter := now.Add(validity)
	if notAfter.After(c.intermediateCert.NotAfter) {
		notAfter = c.intermediateCert.NotAfter
	}

	// RSA keys can also be used for key exchange in older TLS versions.
	keyUsage := x509.KeyUsageDigitalSignature
	if _, isRSA := req.PublicKey.(*rsa.PublicKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	if req.Template.KeyUsage != 0 {
		keyUsage = req.Template.KeyUsage
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization:       c.intermediateCert.Subject.Organization,
			OrganizationalUnit: req.Template.OrganizationalUnit,
			CommonName:         req.CommonName,
		},
		Policies:              policyOIDs(req.Template.Policies),
		ExtraExtensions:       req.Template.Extensions,
		DNSNames:              req.DNSNames,
		IPAddresses:           req.IPAddresses,
		EmailAddresses:        req.EmailAddresses,
		NotBefore:             now.Add(-backdate),
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           req.Template.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	// Where to ask about this certificate later.
	if c.publicURL != "" {
		template.CRLDistributionPoints = []string{c.publicURL + CRLPath}
		template.OCSPServer = []string{c.publicURL + OCSPPath}
		template.IssuingCertificateURL = []string{c.publicURL + IntermediateCertPath}
	}

	cert, err := signCert(template, c.intermediateCert, req.PublicKey, c.intermediateKey)
	if err != nil {
		return nil, err
	}
	// Not handed out, and not recorded, if clients would refuse it.
	if err := c.checkConstraints(cert); err != nil {
		return nil, err
	}
	if c.recorder != nil {
		kind := req.Template.Name
		if req.RecordAs != "" {
			kind = req.RecordAs
		}
		if err := c.recorder.RecordX509(cert, kind, req.Protocol); err != nil {
			return nil, fmt.Errorf("%s certificate: cannot record it, so it is not issued: %w", req.Template.Name, err)
		}
	}
	return cert, nil
}

func checkX509Request(req X509Request) error {
	if req.Template.Name == "" {
		return errors.New("no profile given")
	}
	if req.PublicKey == nil {
		return errors.New("no public key given")
	}
	if err := checkPublicKey(req.PublicKey); err != nil {
		return err
	}

	hasHostName := len(req.DNSNames) > 0 || len(req.IPAddresses) > 0
	if req.Template.RequireHostName && !hasHostName {
		return errors.New("at least one DNS name or IP address is required")
	}
	if req.CommonName == "" && !hasHostName && len(req.EmailAddresses) == 0 {
		return errors.New("a common name, DNS name, IP address or email address is required")
	}
	for _, name := range req.DNSNames {
		if name == "" {
			return errors.New("empty DNS name")
		}
	}
	for _, email := range req.EmailAddresses {
		if email == "" {
			return errors.New("empty email address")
		}
	}
	return nil
}
