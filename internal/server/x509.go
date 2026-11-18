// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/metrics"
	"github.com/bastionxp/bastionxp-ca/internal/policy"
	"github.com/bastionxp/bastionxp-ca/internal/store"
	"github.com/bastionxp/bastionxp-ca/internal/token"
)

// handleSignX509 signs one TLS certificate.
func (s *Server) handleSignX509(w http.ResponseWriter, r *http.Request) {
	// Verifier: who is asking? Here, the holder of a token.
	grant, ok := s.verifyToken(w, r)
	if !ok {
		return
	}

	var body api.SignX509Request
	if !readJSON(w, r, &body) {
		return
	}
	csr, err := parseCSR(body.CSR)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	validity, err := parseValidity(body.Validity)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	cert, refused := s.issueX509(r.Context(), grant, csr, validity, "api", r.RemoteAddr)
	if refused != nil {
		writeError(w, refused.status, refused.message)
		return
	}
	writeJSON(w, http.StatusCreated, api.SignX509Response{
		Certificate: string(ca.EncodeCertPEM(cert)),
		Chain:       string(ca.EncodeCertPEM(append([]*x509.Certificate{cert}, s.ca.Chain()...)...)),
	})
}

// refusal says why a certificate was not issued: the HTTP status that
// fits, and a message for the requester.
type refusal struct {
	status  int
	message string
}

// issueX509 issues the certificate that a token allows for a CSR. It is
// the road every X.509 certificate from a token takes, whichever protocol
// the request came by: template, policy, one-time check, CA.
//
// protocol ("api" or "scep") and remote are for the log.
func (s *Server) issueX509(ctx context.Context, grant *token.Grant, csr *x509.CertificateRequest, validity time.Duration, protocol, remote string) (*x509.Certificate, *refusal) {
	// Template: the token says which kind of certificate it is for.
	template, ok := s.ca.X509Template(grant.Template)
	if !ok {
		return nil, &refusal{http.StatusForbidden,
			fmt.Sprintf("this token is for %q certificates, which this endpoint does not issue", grant.Template)}
	}
	req, err := ca.RequestFromCSR(template, csr)
	if err != nil {
		return nil, &refusal{http.StatusBadRequest, err.Error()}
	}
	req.Validity = validity
	req.Protocol = ca.ProtocolAPI
	if protocol == "scep" {
		req.Protocol = ca.ProtocolSCEP
	}

	// Policy: may the holder of this token have these names?
	if err := policy.CheckX509(grant.Names, req); err != nil {
		s.log.Warn("request refused", "error", err, "token_id", grant.ID, "remote", remote)
		s.metrics.Refused(metrics.RefusedPolicy)
		return nil, &refusal{http.StatusForbidden, err.Error()}
	}
	// A token that is tied to one key only works for that key.
	fingerprint, err := ca.X509Fingerprint(req.PublicKey)
	if err != nil {
		return nil, &refusal{http.StatusBadRequest, err.Error()}
	}
	if grant.KeyFingerprint != "" && grant.KeyFingerprint != fingerprint {
		s.log.Warn("request refused: token is for another key", "token_id", grant.ID, "remote", remote)
		s.metrics.Refused(metrics.RefusedWrongKey)
		return nil, &refusal{http.StatusForbidden, "not allowed: this token was made for another key"}
	}

	// One-time: from here on the token is spent, even if signing fails.
	// Doing this right before signing means two requests with the same
	// token can never both get a certificate.
	err = s.store.UseToken(ctx, grant.ID, grant.Expires)
	if errors.Is(err, store.ErrTokenUsed) {
		s.log.Warn("token used twice", "token_id", grant.ID, "remote", remote)
		s.metrics.Refused(metrics.RefusedUsed)
		return nil, &refusal{http.StatusUnauthorized, "this token was already used"}
	}
	if err != nil {
		s.log.Error("cannot record token use", "error", err)
		return nil, &refusal{http.StatusInternalServerError, "internal error"}
	}

	// CA: sign.
	cert, err := s.ca.IssueX509(req)
	if err != nil {
		// IssueX509 refuses requests that are not sound: weak key,
		// validity above the maximum, missing host name.
		s.log.Warn("certificate not issued", "error", err, "token_id", grant.ID)
		s.metrics.Refused(metrics.RefusedUnsound)
		return nil, &refusal{http.StatusBadRequest, err.Error()}
	}

	s.metrics.Issued(template.Name, issuedVerifier(grant, protocol))
	s.log.Info("certificate issued",
		"profile", template.Name,
		"serial", cert.SerialNumber.Text(16),
		"common_name", cert.Subject.CommonName,
		"dns_names", cert.DNSNames,
		"ip_addresses", cert.IPAddresses,
		"email_addresses", cert.EmailAddresses,
		"not_after", cert.NotAfter.UTC().Format(time.RFC3339),
		"verifier", verifierName(grant),
		"protocol", protocol,
		"subject", grant.Subject,
		"created_by", grant.CreatedBy,
		"token_id", grant.ID,
		"remote", remote,
	)
	return cert, nil
}

// issueForSCEP is what the SCEP server calls for each request. The
// challenge of a SCEP request is a one-time token.
func (s *Server) issueForSCEP(ctx context.Context, challenge string, csr *x509.CertificateRequest, remote string) (*x509.Certificate, error) {
	// The shared password, if one is configured; otherwise a token.
	if s.static.matches(challenge) {
		return s.issueStaticSCEP(ctx, csr, remote)
	}
	// Verifier: who is asking? The holder of the token in the challenge.
	grant, err := s.tokens.Verify(challenge)
	if err != nil {
		s.log.Warn("token refused", "error", err, "protocol", "scep", "remote", remote)
		s.metrics.Refused(metrics.RefusedToken)
		return nil, errors.New("the challenge is not a valid token")
	}
	// SCEP has no way to ask for a validity: the template's default applies.
	cert, refused := s.issueX509(ctx, grant, csr, 0, "scep", remote)
	if refused != nil {
		return nil, errors.New(refused.message)
	}
	return cert, nil
}

// renewForSCEP renews over SCEP (RenewalReq), by the same rules as
// handleRenewX509: a valid certificate of this CA, in its list and not
// revoked, renewed with its names and profile. The key may be the same
// (RFC 8894 allows it; see scep.Server.decideRenewal). The SCEP message
// was signed with old's key, and the CSR's signature is checked.
func (s *Server) renewForSCEP(ctx context.Context, old *x509.Certificate, csr *x509.CertificateRequest, remote string) (*x509.Certificate, error) {
	roots, intermediates := s.ownCertPools()
	if _, err := old.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		s.log.Warn("renewal refused", "error", err, "protocol", "scep", "remote", remote)
		s.metrics.Refused(metrics.RefusedToken)
		return nil, errors.New("the certificate that signed the request is not a valid certificate of this CA: it may have expired")
	}
	record, err := s.renewableRecord(ctx, store.KindX509, store.X509Serial(old.SerialNumber), sameX509(old), remote)
	if err != nil {
		return nil, err
	}
	// Renewed only the way it was obtained.
	if record.Protocol != ca.ProtocolSCEP {
		s.log.Warn("renewal refused: not a SCEP certificate", "serial", record.Serial, "obtained_with", record.Protocol, "protocol", "scep", "remote", remote)
		s.metrics.Refused(metrics.RefusedToken)
		return nil, errors.New(renewElsewhere(record.Protocol))
	}
	template, ok := s.ca.X509Template(record.Template)
	if !ok {
		return nil, errors.New("certificates of the kind " + record.Template + " cannot be renewed this way")
	}
	return s.renewX509(old, template, csr.PublicKey, ca.ProtocolSCEP, "scep_renewal", remote)
}

// lookupForSCEP returns a certificate of this CA by serial number, for
// SCEP's GetCert; nil if there is none.
func (s *Server) lookupForSCEP(ctx context.Context, serial *big.Int) (*x509.Certificate, error) {
	record, err := s.store.Certificate(ctx, store.KindX509, store.X509Serial(serial))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(record.Body))
	if block == nil {
		return nil, errors.New("the stored certificate is not PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// parseCSR reads a certificate signing request in PEM format.
func parseCSR(pemText string) (*x509.CertificateRequest, error) {
	if pemText == "" {
		return nil, errors.New(`"csr" is required: a certificate signing request in PEM format`)
	}
	block, _ := pem.Decode([]byte(pemText))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New(`"csr" is not a PEM certificate signing request`)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot read the CSR: %w", err)
	}
	return csr, nil
}
