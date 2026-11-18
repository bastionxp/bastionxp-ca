// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// ACME Renewal Information (RFC 9773): the CA tells clients when to renew
// a certificate. Normally that is when a third of its lifetime is left,
// as "bxp renew" does. A revoked certificate, or one issued by an
// intermediate that has since been replaced (it can no longer be revoked),
// should be renewed now.
//
// A client asks with a plain GET, no signature: renewal-info/<certID>.

// RenewalInfoPath is where renewal information is served, followed by
// "/<certID>".
const RenewalInfoPath = "/acme/renewal-info"

// renewalInfoRetryAfter is how long clients wait before they ask again.
// An hour lets a revocation reach long-running clients (Caddy, Traefik)
// within the hour.
const renewalInfoRetryAfter = time.Hour

type renewalInfoJSON struct {
	SuggestedWindow windowJSON `json:"suggestedWindow"`
}

type windowJSON struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// CertID returns a certificate's ID in RFC 9773 form:
// base64url(authority key ID) "." base64url(serial number, DER content).
func CertID(cert *x509.Certificate) (string, error) {
	der, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return "", err
	}
	var serial asn1.RawValue
	if _, err := asn1.Unmarshal(der, &serial); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(cert.AuthorityKeyId) + "." +
		base64.RawURLEncoding.EncodeToString(serial.Bytes), nil
}

// ParseCertID reads an RFC 9773 certificate ID: the authority key ID and
// the serial number.
func ParseCertID(id string) (authorityKeyID []byte, serial *big.Int, err error) {
	akiText, serialText, ok := strings.Cut(id, ".")
	if !ok || akiText == "" || serialText == "" || strings.Contains(serialText, ".") {
		return nil, nil, errors.New("a certificate ID is <authority key ID>.<serial number>, both base64url")
	}
	aki, err := base64.RawURLEncoding.DecodeString(akiText)
	if err != nil {
		return nil, nil, fmt.Errorf("the authority key ID is not base64url without padding: %w", err)
	}
	serialBytes, err := base64.RawURLEncoding.DecodeString(serialText)
	if err != nil {
		return nil, nil, fmt.Errorf("the serial number is not base64url without padding: %w", err)
	}
	if len(serialBytes) == 0 || serialBytes[0]&0x80 != 0 {
		return nil, nil, errors.New("the serial number is not a positive number")
	}
	return aki, new(big.Int).SetBytes(serialBytes), nil
}

// badCertIDError is a certificate ID the client got wrong.
type badCertIDError struct{ error }

// lookupCertID finds the certificate a certificate ID names, among those
// this CA issued. It returns store.ErrNotFound for any other, and a
// badCertIDError for an ID that is not one.
func (s *Server) lookupCertID(r *http.Request, id string) (*x509.Certificate, *store.Certificate, error) {
	aki, serial, err := ParseCertID(id)
	if err != nil {
		return nil, nil, badCertIDError{err}
	}
	record, err := s.store.Certificate(r.Context(), store.KindX509, store.X509Serial(serial))
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode([]byte(record.Body))
	if block == nil {
		return nil, nil, fmt.Errorf("certificate %s: no PEM in the database", record.Serial)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate %s: %w", record.Serial, err)
	}
	// Same serial, but another issuer: not this certificate.
	if !bytes.Equal(cert.AuthorityKeyId, aki) {
		return nil, nil, store.ErrNotFound
	}
	return cert, record, nil
}

// renewalWindow is when a certificate should be renewed.
func (s *Server) renewalWindow(cert *x509.Certificate, record *store.Certificate, now time.Time) (start, end time.Time) {
	// Renew now: the window lies just behind, so that a client whose
	// clock is a little slow still finds part of it in its past.
	if record.Revoked() || !bytes.Equal(cert.AuthorityKeyId, s.ca.IntermediateCert().SubjectKeyId) {
		return now.Add(-time.Hour), now
	}
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	return cert.NotBefore.Add(lifetime * 2 / 3), cert.NotBefore.Add(lifetime * 5 / 6)
}

// handleRenewalInfo answers GET renewal-info/<certID>.
func (s *Server) handleRenewalInfo(w http.ResponseWriter, r *http.Request) {
	cert, record, err := s.lookupCertID(r, r.PathValue("id"))
	var bad badCertIDError
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.writeProblem(w, r, http.StatusNotFound, errMalformed, "this CA did not issue a certificate with this ID")
		return
	case errors.As(err, &bad):
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "invalid certificate ID: "+bad.Error())
		return
	case err != nil:
		s.writeInternalError(w, r, "cannot read certificate", err)
		return
	}
	start, end := s.renewalWindow(cert, record, time.Now())
	w.Header().Set("Retry-After", strconv.Itoa(int(renewalInfoRetryAfter.Seconds())))
	s.writeJSON(w, r, http.StatusOK, renewalInfoJSON{SuggestedWindow: windowJSON{
		Start: start.UTC().Format(time.RFC3339),
		End:   end.UTC().Format(time.RFC3339),
	}})
}

// checkReplaces checks the "replaces" of a new order (RFC 9773, section
// 5): the certificate is one of this CA's, issued to the same account, and
// shares a name with the order. It writes the refusal and returns false,
// or returns true.
func (s *Server) checkReplaces(w http.ResponseWriter, r *http.Request, id, accountID string, names []string) bool {
	_, record, err := s.lookupCertID(r, id)
	var bad badCertIDError
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "replaces: this CA did not issue a certificate with this ID")
		return false
	case errors.As(err, &bad):
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "replaces: invalid certificate ID: "+bad.Error())
		return false
	case err != nil:
		s.writeInternalError(w, r, "cannot read the certificate to replace", err)
		return false
	}
	owner, err := s.store.ACMEAccountOfCertificate(r.Context(), record.Serial)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.writeInternalError(w, r, "cannot read the certificate's order", err)
		return false
	}
	if owner != accountID {
		s.writeProblem(w, r, http.StatusForbidden, errUnauthorized, "replaces: the certificate was not issued to this account")
		return false
	}
	for _, name := range names {
		for _, old := range record.Names {
			if strings.EqualFold(name, old) {
				return true
			}
		}
	}
	s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "replaces: the order has no name in common with the certificate it replaces")
	return false
}
