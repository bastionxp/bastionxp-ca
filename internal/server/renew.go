// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/metrics"
	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// This file is renewal: a machine that has a certificate of this CA gets
// the next one by itself, with no token and nobody's help.
//
//	POST /v1/x509/renew   a TLS certificate, for a new key
//	POST /v1/ssh/renew    an SSH host certificate, for the same host key
//
// The proof is not a token from an administrator. It is the certificate
// itself, plus a signature with its private key (see api.ProofClaims).
// The new certificate gets exactly the names of the old one: renewal can
// keep what a machine has, but never give it more.
//
// A certificate that has expired, or was revoked, cannot be renewed. That
// is what stops a stolen key from being renewed forever.

// proofAlgorithms are the ways a proof may be signed: the key types the
// CA issues certificates for.
var proofAlgorithms = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512, jose.RS256, jose.EdDSA,
}

// clockLeeway allows for a client whose clock is a little off.
const clockLeeway = time.Minute

// renewal is a renew request after its proof has been read but not yet
// checked: the token, its one header and the body.
type renewal struct {
	token  *jwt.JSONWebToken
	header jose.Header
	body   []byte
}

// readRenewal reads the body and parses the proof. It sends the error
// answer itself and returns nil on failure.
func (s *Server) readRenewal(w http.ResponseWriter, r *http.Request) *renewal {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "cannot read the request")
		return nil
	}
	token, err := jwt.ParseSigned(bearerToken(r), proofAlgorithms)
	if err != nil || len(token.Headers) != 1 {
		writeError(w, http.StatusUnauthorized, "missing or invalid renewal proof")
		return nil
	}
	return &renewal{token: token, header: token.Headers[0], body: body}
}

// checkProof checks that the proof is signed with key, is meant for this
// kind of renewal, is fresh, and covers this request's body. It returns
// the proof's ID and expiry, for the one-time check.
func checkProof(rn *renewal, key crypto.PublicKey, audience string) (id string, expires time.Time, err error) {
	var standard jwt.Claims
	var claims api.ProofClaims
	if err := rn.token.Claims(key, &standard, &claims); err != nil {
		return "", time.Time{}, errors.New("the proof is not signed with the certificate's key")
	}
	now := time.Now()
	if err := standard.ValidateWithLeeway(jwt.Expected{AnyAudience: jwt.Audience{audience}, Time: now}, clockLeeway); err != nil {
		return "", time.Time{}, errors.New("the proof is expired or meant for something else: " + err.Error())
	}
	// A proof must be short-lived, and say so. One without an expiry,
	// or valid for longer, could be kept and used later.
	if standard.Expiry == nil || standard.ID == "" ||
		standard.Expiry.Time().After(now.Add(api.ProofMaxLifetime+clockLeeway)) {
		return "", time.Time{}, errors.New("the proof must have an ID and expire within 5 minutes")
	}
	sum := sha256.Sum256(rn.body)
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(claims.BodySHA256), []byte(want)) != 1 {
		return "", time.Time{}, errors.New("the proof is for another request")
	}
	return standard.ID, standard.Expiry.Time(), nil
}

// useProof makes sure a proof works once: a request that was captured
// cannot be sent again. Proofs share the table of used one-time tokens.
func (s *Server) useProof(w http.ResponseWriter, r *http.Request, id string, expires time.Time) bool {
	err := s.store.UseToken(r.Context(), "renew:"+id, expires)
	if errors.Is(err, store.ErrTokenUsed) {
		s.log.Warn("renewal proof used twice", "remote", r.RemoteAddr)
		s.metrics.Refused(metrics.RefusedUsed)
		writeError(w, http.StatusUnauthorized, "this renewal proof was already used")
		return false
	}
	if err != nil {
		s.log.Error("cannot record renewal proof", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return false
	}
	return true
}

// recordFor looks up the record of a certificate and checks that it is
// exactly this certificate and not revoked. It sends the error answer
// itself and returns nil on failure.
func (s *Server) recordFor(w http.ResponseWriter, r *http.Request, kind, serial string, same func(body string) bool) *store.Certificate {
	record, err := s.renewableRecord(r.Context(), kind, serial, same, r.RemoteAddr)
	if errors.Is(err, errInternal) {
		writeError(w, http.StatusInternalServerError, "internal error")
		return nil
	}
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return nil
	}
	return record
}

// renewElsewhere says how to renew a certificate that was obtained with
// protocol.
func renewElsewhere(protocol string) string {
	switch protocol {
	case ca.ProtocolACME:
		return "this certificate came from ACME: renew it with your ACME client (bxp acme renew, certbot renew, ...)"
	case ca.ProtocolSCEP:
		return "this certificate came from SCEP: renew it over SCEP (bxp scep renew, or the device's SCEP renewal)"
	case ca.ProtocolAPI:
		return "this certificate came from BastionXP CA's API: renew it with bxp renew"
	}
	return "this certificate cannot be renewed this way"
}

// errInternal stands for a failure that is ours, not the requester's.
var errInternal = errors.New("internal error")

// renewableRecord is recordFor for any protocol: the error says why the
// certificate cannot be renewed, or is errInternal.
func (s *Server) renewableRecord(ctx context.Context, kind, serial string, same func(body string) bool, remote string) (*store.Certificate, error) {
	record, err := s.store.Certificate(ctx, kind, serial)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !same(record.Body)) {
		// Signed by our key but not in our list: never ours to renew.
		s.log.Warn("renewal refused: certificate not in the list", "kind", kind, "serial", serial, "remote", remote)
		s.metrics.Refused(metrics.RefusedToken)
		return nil, errors.New("this CA has no record of the certificate, so it cannot be renewed")
	}
	if err != nil {
		s.log.Error("cannot read certificate", "error", err)
		return nil, errInternal
	}
	if record.Revoked() {
		s.log.Warn("renewal refused: certificate is revoked", "kind", kind, "serial", serial, "remote", remote)
		s.metrics.Refused(metrics.RefusedToken)
		return nil, errors.New("the certificate was revoked, so it cannot be renewed: get a new one with a token")
	}
	return record, nil
}

// sameX509 returns the check that a stored certificate is cert.
func sameX509(cert *x509.Certificate) func(body string) bool {
	return func(body string) bool {
		block, _ := pem.Decode([]byte(body))
		return block != nil && bytes.Equal(block.Bytes, cert.Raw)
	}
}

// renewX509 issues the renewal of old for a new key: old's names and
// profile, for as long as old was valid. protocol is how old was obtained,
// and stays with the new certificate; verifier is "renewal" or
// "scep_renewal".
func (s *Server) renewX509(old *x509.Certificate, template ca.X509Template, key crypto.PublicKey, protocol, verifier, remote string) (*x509.Certificate, error) {
	cert, err := s.ca.IssueX509(ca.X509Request{
		Protocol:       protocol,
		Template:       template,
		PublicKey:      key,
		CommonName:     old.Subject.CommonName,
		DNSNames:       old.DNSNames,
		IPAddresses:    old.IPAddresses,
		EmailAddresses: old.EmailAddresses,
		Validity:       renewedValidity(old.NotBefore, old.NotAfter, template.MaxValidity),
	})
	if err != nil {
		return nil, err
	}
	s.metrics.Issued(template.Name, verifier)
	s.log.Info("certificate renewed",
		"profile", template.Name,
		"old_serial", old.SerialNumber.Text(16),
		"serial", cert.SerialNumber.Text(16),
		"common_name", cert.Subject.CommonName,
		"dns_names", cert.DNSNames,
		"ip_addresses", cert.IPAddresses,
		"not_after", cert.NotAfter.UTC().Format(time.RFC3339),
		"verifier", verifier,
		"remote", remote,
	)
	return cert, nil
}

// ownCertPools returns the pools to verify a certificate of this CA.
func (s *Server) ownCertPools() (roots, intermediates *x509.CertPool) {
	roots = x509.NewCertPool()
	roots.AddCert(s.ca.RootCert())
	intermediates = x509.NewCertPool()
	for _, c := range s.ca.Chain() {
		intermediates.AddCert(c)
	}
	// Certificates of a replaced intermediate are renewed onto the
	// current one (see ca.ReplacedIntermediates).
	for _, c := range s.ca.ReplacedIntermediates() {
		intermediates.AddCert(c)
	}
	return roots, intermediates
}

// renewedValidity returns how long the new certificate should be valid:
// as long as the old one was. The CA starts every certificate a minute in
// the past, so that minute comes off.
func renewedValidity(notBefore, notAfter time.Time, maxValidity time.Duration) time.Duration {
	validity := (notAfter.Sub(notBefore) - time.Minute).Round(time.Second)
	if validity <= 0 || validity > maxValidity {
		return 0 // the template's default
	}
	return validity
}

// handleRenewX509 renews a TLS certificate.
func (s *Server) handleRenewX509(w http.ResponseWriter, r *http.Request) {
	rn := s.readRenewal(w, r)
	if rn == nil {
		return
	}

	// Verifier: who is asking? The holder of a certificate of this CA.
	// Certificates checks the chain to our root, and the expiry time.
	roots, intermediates := s.ownCertPools()
	chains, err := rn.header.Certificates(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil || len(chains) == 0 {
		s.log.Warn("renewal refused", "error", err, "remote", r.RemoteAddr)
		s.metrics.Refused(metrics.RefusedToken)
		writeError(w, http.StatusUnauthorized, "the certificate in the proof is not a valid certificate of this CA: it may have expired")
		return
	}
	old := chains[0][0]
	id, expires, err := checkProof(rn, old.PublicKey, api.ProofAudienceX509)
	if err != nil {
		s.log.Warn("renewal refused", "error", err, "serial", old.SerialNumber.Text(16), "remote", r.RemoteAddr)
		s.metrics.Refused(metrics.RefusedUnsound)
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Policy: is it a certificate we issued, still in good standing, of
	// a kind that may be renewed?
	record := s.recordFor(w, r, store.KindX509, store.X509Serial(old.SerialNumber), sameX509(old))
	if record == nil {
		return
	}
	// Renewed only the way it was obtained: an ACME certificate by its
	// ACME client, a SCEP certificate over SCEP.
	if record.Protocol != ca.ProtocolAPI {
		s.log.Warn("renewal refused: not obtained through the API", "serial", record.Serial, "obtained_with", record.Protocol, "remote", r.RemoteAddr)
		s.metrics.Refused(metrics.RefusedToken)
		writeError(w, http.StatusForbidden, renewElsewhere(record.Protocol))
		return
	}
	template, ok := s.ca.X509Template(record.Template)
	if !ok {
		writeError(w, http.StatusForbidden, "certificates of the kind "+record.Template+" cannot be renewed this way")
		return
	}

	var body api.RenewX509Request
	decoder := json.NewDecoder(bytes.NewReader(rn.body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	csr, err := parseCSR(body.CSR)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := csr.CheckSignature(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid CSR signature")
		return
	}
	// A new certificate is the moment for a new key. Keeping the old
	// one would also keep it valid for as long as renewals go on.
	if sameKey(csr.PublicKey, old.PublicKey) {
		writeError(w, http.StatusBadRequest, "the CSR must be for a new key, not the key of the old certificate")
		return
	}

	if !s.useProof(w, r, id, expires) {
		return
	}

	// CA: sign, with the old certificate's names and nothing else.
	cert, err := s.renewX509(old, template, csr.PublicKey, ca.ProtocolAPI, "renewal", r.RemoteAddr)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, api.SignX509Response{
		Certificate: string(ca.EncodeCertPEM(cert)),
		Chain:       string(ca.EncodeCertPEM(append([]*x509.Certificate{cert}, s.ca.Chain()...)...)),
	})
}

// handleRenewSSH renews an SSH host certificate. User certificates are
// not renewed this way: they are short-lived, and people log in again.
func (s *Server) handleRenewSSH(w http.ResponseWriter, r *http.Request) {
	rn := s.readRenewal(w, r)
	if rn == nil {
		return
	}

	// Verifier: who is asking? The holder of a host certificate of
	// this CA, and of the host key it is for.
	line, _ := rn.header.ExtraHeaders[jose.HeaderKey(api.ProofSSHCertHeader)].(string)
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	old, isCert := parsed.(*ssh.Certificate)
	if err != nil || !isCert {
		writeError(w, http.StatusUnauthorized, "the proof carries no SSH certificate")
		return
	}
	if old.CertType != ssh.HostCert {
		writeError(w, http.StatusForbidden, "only SSH host certificates are renewed; for a user certificate, log in again")
		return
	}
	// Signed with the host CA key, or one it replaced: hosts move to a
	// new host CA key by renewing.
	if !s.ca.IsOwnSSHHostCA(old.SignatureKey) || len(old.ValidPrincipals) == 0 {
		writeError(w, http.StatusUnauthorized, "the SSH certificate in the proof is not from this CA")
		return
	}
	// CheckCert checks the CA's signature on the certificate and that it
	// has not expired.
	if err := (&ssh.CertChecker{}).CheckCert(old.ValidPrincipals[0], old); err != nil {
		writeError(w, http.StatusUnauthorized, "the SSH certificate in the proof is not valid: it may have expired")
		return
	}
	hostKey, ok := old.Key.(ssh.CryptoPublicKey)
	if !ok {
		writeError(w, http.StatusBadRequest, "the host key cannot sign a renewal proof")
		return
	}
	id, expires, err := checkProof(rn, hostKey.CryptoPublicKey(), api.ProofAudienceSSH)
	if err != nil {
		s.log.Warn("renewal refused", "error", err, "serial", old.Serial, "remote", r.RemoteAddr)
		s.metrics.Refused(metrics.RefusedUnsound)
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Policy: is it a certificate we issued, still in good standing?
	record := s.recordFor(w, r, store.KindSSH, store.SSHSerial(old.Serial), func(body string) bool {
		return strings.TrimSpace(body) == strings.TrimSpace(line)
	})
	if record == nil {
		return
	}
	// Its profile as it is now: ssh-host, or one of the administrator's
	// host profiles.
	template, ok := s.ca.SSHTemplate(record.Template)
	if !ok || template.CertType != ssh.HostCert {
		writeError(w, http.StatusForbidden, "only SSH host certificates are renewed")
		return
	}
	var body api.RenewSSHRequest
	decoder := json.NewDecoder(bytes.NewReader(rn.body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	if !s.useProof(w, r, id, expires) {
		return
	}

	// CA: sign, for the same host key, the same principals and key ID.
	cert, err := s.ca.IssueSSH(ca.SSHRequest{
		Template:   template,
		PublicKey:  old.Key,
		KeyID:      old.KeyId,
		Principals: old.ValidPrincipals,
		Validity: renewedValidity(time.Unix(int64(old.ValidAfter), 0), time.Unix(int64(old.ValidBefore), 0),
			template.MaxValidity),
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.metrics.Issued(template.Name, "renewal")
	s.log.Info("certificate renewed",
		"profile", template.Name,
		"old_serial", old.Serial,
		"serial", cert.Serial,
		"key_id", cert.KeyId,
		"principals", cert.ValidPrincipals,
		"not_after", time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.RFC3339),
		"verifier", "renewal",
		"remote", r.RemoteAddr,
	)
	writeJSON(w, http.StatusCreated, api.SignSSHResponse{Certificate: string(ssh.MarshalAuthorizedKey(cert))})
}

// sameKey reports whether two public keys are the same key.
func sameKey(a, b crypto.PublicKey) bool {
	type equaler interface {
		Equal(crypto.PublicKey) bool
	}
	ka, ok := a.(equaler)
	return ok && ka.Equal(b)
}
