// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package scep

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"io"
	"log/slog"
	"math/big"
	"net/http"

	"go.mozilla.org/pkcs7"
)

// maxBodyBytes limits the size of a request.
const maxBodyBytes = 128 * 1024

// IssueFunc decides whether the holder of a challenge may have a
// certificate for a CSR, and if so has the CA sign it. remote is the
// address of the device, for the log.
//
// The SCEP server knows nothing about tokens, policy or the CA's keys.
// It unpacks the request, calls this function, and packs the answer.
type IssueFunc func(ctx context.Context, challenge string, csr *x509.CertificateRequest, remote string) (*x509.Certificate, error)

// RenewFunc decides whether the holder of old, a certificate of the CA,
// may have a new one for the key in csr, and if so has the CA sign it.
// The request was signed with old's key; the CSR's signature is checked.
type RenewFunc func(ctx context.Context, old *x509.Certificate, csr *x509.CertificateRequest, remote string) (*x509.Certificate, error)

// LookupFunc returns the certificate the CA issued with this serial
// number, or nil if there is none.
type LookupFunc func(ctx context.Context, serial *big.Int) (*x509.Certificate, error)

// Options are what a Server needs. All fields are required, except where
// noted.
type Options struct {
	RA *RA
	// CACerts are the CA's certificates that devices should learn,
	// usually the intermediate and the root.
	CACerts []*x509.Certificate
	Issue   IssueFunc
	// Renew handles renewals (RenewalReq). Optional: without it,
	// renewals are refused and not advertised.
	Renew RenewFunc
	// Lookup handles GetCert. Optional: without it, GetCert is refused.
	Lookup LookupFunc
	Log    *slog.Logger
}

// Server is the SCEP server. Create one with New and serve it at Path.
type Server struct {
	ra      *RA
	caCerts []*x509.Certificate
	issue   IssueFunc
	renew   RenewFunc
	lookup  LookupFunc
	log     *slog.Logger
}

// New returns a SCEP server.
func New(opts Options) *Server {
	return &Server{ra: opts.RA, caCerts: opts.CACerts, issue: opts.Issue, renew: opts.Renew, lookup: opts.Lookup, log: opts.Log}
}

// ServeHTTP answers a SCEP request. All of SCEP uses one address; the
// "operation" parameter says what is wanted.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("operation") {
	case "GetCACaps":
		w.Header().Set("Content-Type", "text/plain")
		caps := capabilities
		if s.renew != nil {
			caps += "Renewal\n"
		}
		io.WriteString(w, caps)
	case "GetCACert":
		s.handleGetCACert(w, r)
	case "PKIOperation":
		s.handlePKIOperation(w, r)
	default:
		http.Error(w, "unknown SCEP operation", http.StatusBadRequest)
	}
}

// handleGetCACert sends the certificates a device needs: the RA's, to
// encrypt its request for, and the CA's, to trust what it gets.
func (s *Server) handleGetCACert(w http.ResponseWriter, r *http.Request) {
	// The RA certificate comes first. A device finds it by what the
	// certificate may be used for, but putting it first helps simple ones.
	all := append([]byte(nil), s.ra.Cert.Raw...)
	for _, cert := range s.caCerts {
		all = append(all, cert.Raw...)
	}
	certs, err := pkcs7.DegenerateCertificate(all)
	if err != nil {
		s.log.Error("SCEP: cannot pack the CA certificates", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-ra-cert")
	w.Write(certs)
}

// handlePKIOperation handles a device's request for a certificate.
func (s *Server) handlePKIOperation(w http.ResponseWriter, r *http.Request) {
	body, ok := readMessage(w, r)
	if !ok {
		return
	}
	req, err := openRequest(body, s.ra)
	if err != nil {
		// A message that cannot be opened cannot be answered in SCEP's
		// own way either: the answer would need its transaction ID.
		s.log.Warn("SCEP request refused", "error", err, "remote", r.RemoteAddr)
		http.Error(w, "the SCEP message cannot be read", http.StatusBadRequest)
		return
	}

	cert, failInfo, reason := s.decide(r, req)
	var reply []byte
	if cert != nil {
		reply, err = successReply(req, cert, s.ra)
	} else {
		s.log.Warn("SCEP request refused", "reason", reason, "transaction", req.transactionID, "remote", r.RemoteAddr)
		reply, err = failureReply(req, failInfo, s.ra)
	}
	if err != nil {
		s.log.Error("SCEP: cannot build the answer", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// A refusal is a normal SCEP answer too: status 200, and the "no"
	// is inside the message.
	w.Header().Set("Content-Type", "application/x-pki-message")
	w.Write(reply)
}

// decide returns the certificate for a request, or why there is none:
// the SCEP failure code for the device and the real reason for the log.
func (s *Server) decide(r *http.Request, req *request) (cert *x509.Certificate, failInfo, reason string) {
	// The answer is encrypted for the certificate that signed the
	// request, and that needs an RSA key.
	if !isRSA(req.signer) {
		return nil, failBadAlgorithm, "the device's key is not an RSA key"
	}
	switch req.messageType {
	case messagePKCSReq:
		return s.decideEnroll(r, req)
	case messageRenewalReq:
		if s.renew == nil {
			return nil, failBadRequest, "renewals are not supported"
		}
		return s.decideRenewal(r, req)
	case messageGetCert:
		if s.lookup == nil {
			return nil, failBadRequest, "GetCert is not supported"
		}
		return s.decideGetCert(r, req)
	}
	return nil, failBadRequest, "message type " + req.messageType + " is not supported: only enrollment (19), renewal (17) and GetCert (21)"
}

// decideEnroll handles a first request (PKCSReq): the challenge decides.
func (s *Server) decideEnroll(r *http.Request, req *request) (cert *x509.Certificate, failInfo, reason string) {
	csr, err := x509.ParseCertificateRequest(req.content)
	if err != nil {
		return nil, failBadRequest, "the content is not a CSR: " + err.Error()
	}
	// The message must be signed with the key the certificate is for.
	// Otherwise a device could ask for a certificate for someone else's
	// key, or get the answer encrypted for a key of its choice.
	if !sameKey(csr.PublicKey, req.signer.PublicKey) {
		return nil, failBadMessageCheck, "the message is not signed with the key in the CSR"
	}
	challenge := Challenge(req.content)
	if challenge == "" {
		return nil, failBadRequest, "the CSR has no challenge password"
	}

	cert, err = s.issue(r.Context(), challenge, csr, r.RemoteAddr)
	if err != nil {
		return nil, failBadRequest, err.Error()
	}
	return cert, "", ""
}

// decideRenewal handles a renewal (RenewalReq, RFC 8894 section 3.3.1.2):
// the request is signed with the device's current certificate and its
// key, and the CSR is for the key of the new certificate. RenewFunc
// decides whether the current certificate is one that may be renewed.
//
// The CSR may be for a new key or for the current one: RFC 8894 section
// 2.5 says a client SHOULD use a new key but MAY keep the old one, and
// many devices keep it (micromdm's scepclient, devices whose key is in
// hardware). Requiring a new key would protect nothing: whoever holds the
// current key could put a new key of their own into the CSR. What stops
// a stolen key is revocation, and RenewFunc refuses revoked certificates.
func (s *Server) decideRenewal(r *http.Request, req *request) (cert *x509.Certificate, failInfo, reason string) {
	csr, err := x509.ParseCertificateRequest(req.content)
	if err != nil {
		return nil, failBadRequest, "the content is not a CSR: " + err.Error()
	}
	// The CSR proves that the device holds the key it names. RFC 8894
	// does not ask for this (section 7.6), but a CSR is always signed.
	if err := csr.CheckSignature(); err != nil {
		return nil, failBadMessageCheck, "the CSR's signature is not valid"
	}
	cert, err = s.renew(r.Context(), req.signer, csr, r.RemoteAddr)
	if err != nil {
		return nil, failBadRequest, err.Error()
	}
	return cert, "", ""
}

// issuerAndSerial is the content of a GetCert request (RFC 5652).
type issuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// decideGetCert hands out a certificate the CA issued before (GetCert,
// RFC 8894 section 3.3.3), for a device that lost it but kept its key.
// Only the holder of the certificate's key gets it: certificates are not
// secret, but the CA's list of names should not be open to everyone.
func (s *Server) decideGetCert(r *http.Request, req *request) (cert *x509.Certificate, failInfo, reason string) {
	var wanted issuerAndSerial
	rest, err := asn1.Unmarshal(req.content, &wanted)
	if err != nil || len(rest) > 0 || wanted.SerialNumber == nil {
		return nil, failBadRequest, "the content is not an issuer and serial number"
	}
	var issuer pkix.RDNSequence
	if rest, err := asn1.Unmarshal(wanted.Issuer.FullBytes, &issuer); err != nil || len(rest) > 0 {
		return nil, failBadRequest, "the issuer is not a name"
	}
	serial := wanted.SerialNumber.Text(16)
	cert, err = s.lookup(r.Context(), wanted.SerialNumber)
	if err != nil {
		return nil, failBadRequest, "cannot look up the certificate: " + err.Error()
	}
	if cert == nil || !bytes.Equal(cert.RawIssuer, wanted.Issuer.FullBytes) {
		return nil, failBadCertID, "no certificate with serial " + serial + " from that issuer"
	}
	if !sameKey(cert.PublicKey, req.signer.PublicKey) {
		return nil, failBadRequest, "the request for certificate " + serial + " is not signed with its key"
	}
	s.log.Info("SCEP certificate sent again", "serial", serial, "common_name", cert.Subject.CommonName, "remote", r.RemoteAddr)
	return cert, "", ""
}

// readMessage returns the SCEP message of a PKIOperation request. It is
// the body of a POST, or, with old devices, a parameter of a GET.
func readMessage(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	switch r.Method {
	case http.MethodPost:
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			http.Error(w, "cannot read the request", http.StatusBadRequest)
			return nil, false
		}
		return body, true
	case http.MethodGet:
		body, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("message"))
		if err != nil || len(body) == 0 {
			http.Error(w, `the "message" parameter is not base64`, http.StatusBadRequest)
			return nil, false
		}
		return body, true
	default:
		http.Error(w, "use GET or POST", http.StatusMethodNotAllowed)
		return nil, false
	}
}

// sameKey reports whether two public keys are the same key.
func sameKey(a, b crypto.PublicKey) bool {
	type equaler interface {
		Equal(x crypto.PublicKey) bool
	}
	ka, ok := a.(equaler)
	return ok && ka.Equal(b)
}
