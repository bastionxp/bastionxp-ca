// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
)

// NewTLSConfig returns the TLS settings for the CA's own HTTPS server.
//
// The server needs a certificate, and it is a CA, so it issues one to
// itself: a normal tls-server certificate for the given names (DNS names
// or IP addresses). Clients that trust the root certificate trust the
// server. The certificate is replaced automatically before it expires, so
// the server can run for years without a restart.
func NewTLSConfig(authority *ca.CA, names []string) (*tls.Config, error) {
	self := &selfCert{ca: authority, names: names}
	// Issue the first certificate now, so that a problem with the names
	// stops the server at startup and not at the first connection.
	if _, err := self.get(time.Now()); err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return self.get(time.Now())
		},
	}, nil
}

// selfCert holds the server's own certificate and renews it when needed.
type selfCert struct {
	ca    *ca.CA
	names []string

	mu      sync.Mutex
	cert    *tls.Certificate
	renewAt time.Time
}

// get returns the current certificate. It issues a new one if there is
// none yet or the current one is past two thirds of its lifetime.
func (s *selfCert) get(now time.Time) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cert != nil && now.Before(s.renewAt) {
		return s.cert, nil
	}

	cert, err := s.issue()
	if err != nil {
		if s.cert != nil {
			// Keep serving with the old certificate. It is still
			// valid for a while, and the next connection tries again.
			return s.cert, nil
		}
		return nil, err
	}
	lifetime := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)
	s.cert = cert
	s.renewAt = cert.Leaf.NotBefore.Add(lifetime * 2 / 3)
	return s.cert, nil
}

// issue creates a new key and has the CA sign a certificate for it.
func (s *selfCert) issue() (*tls.Certificate, error) {
	if len(s.names) == 0 {
		return nil, errors.New("the server needs at least one name for its TLS certificate")
	}

	req := ca.X509Request{Template: ca.TLSServer, CommonName: s.names[0], RecordAs: ca.OwnServerCert}
	for _, name := range s.names {
		if ip := net.ParseIP(name); ip != nil {
			req.IPAddresses = append(req.IPAddresses, ip)
		} else {
			req.DNSNames = append(req.DNSNames, name)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	req.PublicKey = key.Public()

	leaf, err := s.ca.IssueX509(req)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		// Send the intermediate along, so clients only need the root.
		Certificate: chainDER(leaf, s.ca.Chain()),
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// chainDER is the leaf followed by the chain, as a TLS server sends it.
func chainDER(leaf *x509.Certificate, chain []*x509.Certificate) [][]byte {
	out := [][]byte{leaf.Raw}
	for _, c := range chain {
		out = append(out, c.Raw)
	}
	return out
}
