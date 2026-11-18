// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// revocationReasons are the reasons a client may give (RFC 5280 codes):
// the ones the CA uses everywhere else too.
var revocationReasons = map[int]bool{
	ca.ReasonUnspecified:          true,
	ca.ReasonKeyCompromise:        true,
	ca.ReasonSuperseded:           true,
	ca.ReasonCessationOfOperation: true,
}

// handleRevokeCert revokes a certificate (RFC 8555, section 7.6). The
// request is signed either by the account whose order got the
// certificate, or with the certificate's own key ("jwk"): whoever has
// the key may say it must no longer be trusted, even without the
// account.
//
// The revocation is the same as "bxp revoke": the CRL and OCSP show
// it at once.
func (s *Server) handleRevokeCert(w http.ResponseWriter, r *http.Request) {
	req, ok := s.readSigned(w, r, keyOfAccountOrInRequest)
	if !ok {
		return
	}
	var body struct {
		Certificate string `json:"certificate"`
		Reason      *int   `json:"reason"`
	}
	if err := req.decode(&body); err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "invalid revocation request: "+err.Error())
		return
	}
	der, err := base64.RawURLEncoding.DecodeString(body.Certificate)
	if err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, `"certificate" is not base64url`)
		return
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, `"certificate" is not a certificate`)
		return
	}
	reason := ca.ReasonUnspecified
	if body.Reason != nil {
		reason = *body.Reason
	}
	if !revocationReasons[reason] {
		s.writeProblem(w, r, http.StatusBadRequest, errBadRevocationReason,
			"the reason must be 0 (unspecified), 1 (key compromise), 4 (superseded) or 5 (cessation of operation)")
		return
	}

	// Did this CA issue exactly this certificate? The serial number
	// alone is not enough: the request must carry the certificate itself.
	serial := store.X509Serial(cert.SerialNumber)
	record, err := s.store.Certificate(r.Context(), "x509", serial)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.writeInternalError(w, r, "cannot read certificate", err)
		return
	}
	if record == nil || !sameCertificate(record.Body, der) {
		s.writeProblem(w, r, http.StatusNotFound, errMalformed, "this CA did not issue the certificate")
		return
	}

	// May this request revoke it?
	if req.account == nil {
		if !samePublicKey(req.key.Key, cert.PublicKey) {
			s.writeProblem(w, r, http.StatusForbidden, errUnauthorized, "the request is not signed with the certificate's key")
			return
		}
	} else {
		owner, err := s.store.ACMEAccountOfCertificate(r.Context(), serial)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.writeInternalError(w, r, "cannot read order", err)
			return
		}
		if owner != req.account.ID {
			s.writeProblem(w, r, http.StatusForbidden, errUnauthorized,
				"only the account that got the certificate, or the certificate's own key, may revoke it")
			return
		}
	}

	if _, err := s.store.RevokeX509(r.Context(), serial, reason); err != nil {
		if errors.Is(err, store.ErrAlreadyRevoked) {
			s.writeProblem(w, r, http.StatusBadRequest, errAlreadyRevoked, "the certificate was revoked before")
			return
		}
		s.writeInternalError(w, r, "cannot revoke", err)
		return
	}
	signedBy := "certificate key"
	account := ""
	if req.account != nil {
		signedBy, account = "account", req.account.ID
	}
	s.log.Info("certificate revoked over ACME",
		"serial", serial, "reason", reason, "names", cert.DNSNames,
		"signed_by", signedBy, "acme_account", account, "remote", r.RemoteAddr)
	s.addCommonHeaders(w, r)
	w.WriteHeader(http.StatusOK)
}

// sameCertificate reports whether a stored PEM certificate is der.
func sameCertificate(storedPEM string, der []byte) bool {
	block, _ := pem.Decode([]byte(storedPEM))
	return block != nil && string(block.Bytes) == string(der)
}

func samePublicKey(a, b crypto.PublicKey) bool {
	ka, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ka.Equal(b)
}
