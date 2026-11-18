// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/metrics"
)

// SCEP with a static challenge: one password, shared by all devices, for
// device management systems (Jamf, routers) that cannot fetch a one-time
// token per device. Whoever knows the password can enroll, so what a
// device may get is limited: one template, names only in the listed
// domains, no IP addresses, and a number of enrollments per hour.

// SCEPStatic configures the static challenge.
type SCEPStatic struct {
	Challenge    string
	Template     string // tls-client or tls-server
	DNSDomains   []string
	EmailDomains []string
	MaxPerHour   int // 0: no limit
}

type scepStatic struct {
	cfg SCEPStatic

	mu     sync.Mutex
	issued []time.Time // within the last hour
}

func newSCEPStatic(cfg *SCEPStatic) *scepStatic {
	if cfg == nil || cfg.Challenge == "" {
		return nil
	}
	return &scepStatic{cfg: *cfg}
}

// matches compares in constant time, so the answer's timing tells nothing
// about the password.
func (s *scepStatic) matches(challenge string) bool {
	return s != nil && subtle.ConstantTimeCompare([]byte(challenge), []byte(s.cfg.Challenge)) == 1
}

// take counts an enrollment, or reports that the hour's are used up.
func (s *scepStatic) take(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.MaxPerHour == 0 {
		return true
	}
	kept := s.issued[:0]
	for _, t := range s.issued {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
		}
	}
	s.issued = kept
	if len(s.issued) >= s.cfg.MaxPerHour {
		return false
	}
	s.issued = append(s.issued, now)
	return true
}

// checkNames applies the limits on names.
func (s *scepStatic) checkNames(csr *x509.CertificateRequest) error {
	switch {
	case len(csr.IPAddresses) > 0:
		return errors.New("IP addresses are not allowed with the static challenge")
	case len(csr.URIs) > 0:
		return errors.New("URIs are not allowed")
	case len(csr.Subject.CommonName) > 64:
		return errors.New("the common name is too long")
	}
	for _, name := range csr.DNSNames {
		if !inDomains(strings.ToLower(name), s.cfg.DNSDomains) {
			return fmt.Errorf("the DNS name %q is not in the domains allowed with the static challenge", name)
		}
	}
	for _, email := range csr.EmailAddresses {
		_, domain, _ := strings.Cut(email, "@")
		if domain == "" || !inDomains(strings.ToLower(domain), s.cfg.EmailDomains) {
			return fmt.Errorf("the email address %q is not in the domains allowed with the static challenge", email)
		}
	}
	return nil
}

func inDomains(name string, domains []string) bool {
	if strings.Contains(name, "*") {
		return false
	}
	for _, d := range domains {
		d = strings.ToLower(d)
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// issueStaticSCEP issues for a request with the static challenge.
func (s *Server) issueStaticSCEP(_ context.Context, csr *x509.CertificateRequest, remote string) (*x509.Certificate, error) {
	template, ok := s.ca.X509Template(s.static.cfg.Template)
	if !ok {
		return nil, errors.New("internal error")
	}
	if err := s.static.checkNames(csr); err != nil {
		s.log.Warn("request refused", "error", err, "verifier", "scep_static", "remote", remote)
		s.metrics.Refused(metrics.RefusedPolicy)
		return nil, err
	}
	req, err := ca.RequestFromCSR(template, csr)
	if err != nil {
		return nil, err
	}
	req.Protocol = ca.ProtocolSCEP
	if !s.static.take(time.Now()) {
		s.log.Warn("request refused: too many enrollments with the static challenge this hour", "remote", remote)
		s.metrics.Refused(metrics.RefusedRateLimited)
		return nil, errors.New("too many enrollments with the static challenge; try again later")
	}
	cert, err := s.ca.IssueX509(req)
	if err != nil {
		s.log.Warn("certificate not issued", "error", err, "verifier", "scep_static")
		s.metrics.Refused(metrics.RefusedUnsound)
		return nil, err
	}
	s.metrics.Issued(template.Name, "scep_static")
	s.log.Info("certificate issued",
		"profile", template.Name,
		"serial", cert.SerialNumber.Text(16),
		"common_name", cert.Subject.CommonName,
		"dns_names", cert.DNSNames,
		"email_addresses", cert.EmailAddresses,
		"not_after", cert.NotAfter.UTC().Format(time.RFC3339),
		"verifier", "scep_static",
		"protocol", "scep",
		"remote", remote,
	)
	return cert, nil
}
