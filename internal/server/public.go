// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// This file has the CA's public information: things anybody may read,
// and nobody can change through them.
//
//	GET  /root.crt                the root certificate, to install as trusted
//	GET  /intermediate.crt        the certificate that signs all others
//	GET  /ssh_user_ca.pub         for TrustedUserCAKeys on SSH servers
//	GET  /ssh_host_ca.pub         for @cert-authority in known_hosts
//	GET  /v1/certificates/{serial}  one issued certificate
//	GET  /crl                     the list of revoked certificates
//	POST /ocsp, GET /ocsp/{...}   "is this certificate revoked?"
//
// They are served on the main HTTPS address and, if configured, on a
// plain HTTP address as well. Plain HTTP is right for these: everything
// here is either public or signed by the CA, and programs that check
// whether a certificate is revoked often cannot use HTTPS for it.

// Paths of the public endpoints that are not defined in the ca package.
const (
	SSHUserCAPath    = "/ssh_user_ca.pub"
	SSHHostCAPath    = "/ssh_host_ca.pub"
	CertificatesPath = "/v1/certificates/"
)

// maxOCSPRequestBytes limits the size of an OCSP request. A real one is
// about 100 bytes.
const maxOCSPRequestBytes = 16 * 1024

// PublicHandler returns a handler with only the public information: what
// may be served on a plain HTTP address.
func (s *Server) PublicHandler() http.Handler {
	mux := http.NewServeMux()
	s.addPublicRoutes(mux)
	return s.logRequests(s.ocspFirst(mux))
}

// ocspFirst answers GET /ocsp/<request> itself and hands everything else
// to next.
//
// The request in the address is base64, which may contain "//". The mux
// treats an address with "//" as untidy and answers with a redirect to a
// tidied one, which breaks the request. So these never reach the mux.
func (s *Server) ocspFirst(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, ca.OCSPPath+"/") {
			s.handleOCSP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) addPublicRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+ca.RootCertPath, func(w http.ResponseWriter, r *http.Request) {
		writePEM(w, ca.EncodeCertPEM(s.ca.RootCert()))
	})
	mux.HandleFunc("GET "+ca.IntermediateCertPath, func(w http.ResponseWriter, r *http.Request) {
		writePEM(w, ca.EncodeCertPEM(s.ca.IntermediateCert()))
	})
	mux.HandleFunc("GET "+SSHUserCAPath, func(w http.ResponseWriter, r *http.Request) {
		writeText(w, authorizedKeys(s.ca.SSHUserCAPublicKeys()))
	})
	mux.HandleFunc("GET "+SSHHostCAPath, func(w http.ResponseWriter, r *http.Request) {
		writeText(w, authorizedKeys(s.ca.SSHHostCAPublicKeys()))
	})
	mux.HandleFunc("GET "+CertificatesPath+"{serial}", s.handleCertificate)
	mux.HandleFunc("GET "+ca.CRLPath, s.handleCRL)
	mux.HandleFunc("POST "+ca.OCSPPath, s.handleOCSP)
	// GET /ocsp/<request> is handled before the mux: see ocspFirst.
}

func writePEM(w http.ResponseWriter, pemData []byte) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(pemData)
}

func writeText(w http.ResponseWriter, text []byte) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(text)
}

// handleCertificate returns one issued X.509 certificate by its serial
// number. Certificates are not secret: they are shown to everybody the
// holder connects to.
func (s *Server) handleCertificate(w http.ResponseWriter, r *http.Request) {
	serial, err := store.ParseX509Serial(r.PathValue("serial"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	cert, err := s.store.Certificate(r.Context(), store.KindX509, serial)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "this CA has no certificate with that serial number")
		return
	}
	if err != nil {
		s.log.Error("cannot read certificate", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writePEM(w, []byte(cert.Body))
}

// handleCRL returns the list of revoked certificates, signed by the CA.
// It is made fresh for every request, so a revocation shows up at once.
func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	if crl := s.revocations.getCRL(now); crl != nil {
		writeCRL(w, crl)
		return
	}
	certs, err := s.store.RevokedX509(r.Context())
	if err != nil {
		s.log.Error("cannot read revoked certificates", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	var revoked []ca.Revoked
	for _, cert := range certs {
		serial, ok := new(big.Int).SetString(cert.Serial, 16)
		if !ok {
			continue
		}
		revoked = append(revoked, ca.Revoked{Serial: serial, RevokedAt: cert.RevokedAt, Reason: cert.Reason})
	}
	crl, err := s.ca.SignCRL(revoked)
	if err != nil {
		s.log.Error("cannot sign the CRL", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.revocations.putCRL(crl, now)
	writeCRL(w, crl)
}

// publicCacheAge is how long others (proxies, clients) may keep a CRL or
// a GET OCSP answer, in seconds.
const publicCacheAge = "300"

func writeCRL(w http.ResponseWriter, crl []byte) {
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", "public, max-age="+publicCacheAge)
	w.Write(crl)
}

// handleOCSP answers "is this certificate revoked?" for one certificate.
// The question comes as the body of a POST or, base64 encoded, as the
// end of the address of a GET.
func (s *Server) handleOCSP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/ocsp-response")

	var body []byte
	var err error
	if r.Method == http.MethodPost {
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxOCSPRequestBytes))
	} else {
		body, err = decodeOCSPPath(strings.TrimPrefix(r.URL.Path, ca.OCSPPath+"/"))
	}
	var req *ocsp.Request
	if err == nil {
		req, err = ocsp.ParseRequest(body)
	}
	if err != nil {
		// OCSP has its own, unsigned, way to say "I cannot read this".
		w.Write(ocsp.MalformedRequestErrorResponse)
		return
	}

	// A recent answer to the same question is reused.
	now := time.Now()
	ours := s.ca.IssuedByThisCA(req)
	key := req.SerialNumber.Text(16) + "/" + strconv.FormatBool(ours)
	if answer := s.revocations.getOCSP(key, now); answer != nil {
		writeOCSP(w, r, answer)
		return
	}

	// Three possible answers: good, revoked, unknown. "Unknown" is for
	// everything that is not in our list: certificates of other CAs,
	// and above all certificates that claim to be ours and are not.
	var status ca.OCSPStatus
	if ours {
		cert, err := s.store.Certificate(r.Context(), store.KindX509, store.X509Serial(req.SerialNumber))
		switch {
		case err == nil:
			status = ca.OCSPStatus{Known: true, Revoked: cert.Revoked(), RevokedAt: cert.RevokedAt, Reason: cert.Reason}
		case !errors.Is(err, store.ErrNotFound):
			s.log.Error("cannot read certificate", "error", err)
			w.Write(ocsp.InternalErrorErrorResponse)
			return
		}
	}
	answer, err := s.ca.SignOCSP(req.SerialNumber, status)
	if err != nil {
		s.log.Error("cannot sign the OCSP answer", "error", err)
		w.Write(ocsp.InternalErrorErrorResponse)
		return
	}
	s.revocations.putOCSP(key, answer, now)
	writeOCSP(w, r, answer)
}

// writeOCSP sends a signed answer. Answers to GET may be cached by others
// (RFC 5019); POST answers are not cacheable anyway.
func writeOCSP(w http.ResponseWriter, r *http.Request, answer []byte) {
	if r.Method == http.MethodGet {
		w.Header().Set("Cache-Control", "public, max-age="+publicCacheAge)
	}
	w.Write(answer)
}

// decodeOCSPPath reads an OCSP request from the end of an address.
func decodeOCSPPath(encoded string) ([]byte, error) {
	if len(encoded) > 2*maxOCSPRequestBytes {
		return nil, errors.New("too long")
	}
	// The standard says plain base64. Some programs send the URL-safe kind.
	if body, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		return body, nil
	}
	return base64.URLEncoding.DecodeString(encoded)
}

// authorizedKeys writes keys one per line: during a replacement, the
// current key and the next one, which servers and clients should trust
// both.
func authorizedKeys(keys []ssh.PublicKey) []byte {
	var out []byte
	for _, key := range keys {
		out = append(out, ssh.MarshalAuthorizedKey(key)...)
	}
	return out
}
