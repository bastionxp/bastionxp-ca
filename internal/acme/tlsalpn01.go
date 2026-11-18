// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"strings"
)

// alpnProtocol is the TLS protocol name that tells the client's server
// that this connection is the CA's challenge (RFC 8737).
const alpnProtocol = "acme-tls/1"

// idPeAcmeIdentifier is the certificate extension with the SHA-256 of the
// key authorization.
var idPeAcmeIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// checkTLSALPN01 connects to port 443 of name and asks for the protocol
// acme-tls/1. The client's server must answer with a certificate for name
// alone that carries the key authorization's hash in a critical
// acmeIdentifier extension. That means: the holder of the account key
// controls what name serves on port 443.
func (s *Server) checkTLSALPN01(ctx context.Context, name, keyAuth string) *problem {
	ctx, cancel := context.WithTimeout(ctx, challengeTimeout)
	defer cancel()
	address := net.JoinHostPort(name, "443")
	raw, err := s.dial(ctx, "tcp", address)
	if err != nil {
		return newProblem(errConnection, fmt.Sprintf("cannot connect to %s: %v", address, err))
	}
	defer raw.Close()

	// For an IP address, the name sent is its reverse DNS name (RFC 8738).
	serverName := name
	ip := net.ParseIP(name)
	if ip != nil {
		serverName = reverseName(ip)
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName: serverName,
		NextProtos: []string{alpnProtocol},
		MinVersion: tls.VersionTLS12,
		// The certificate is made for the challenge and signed by
		// nobody. What counts is checked below.
		InsecureSkipVerify: true, //nolint:gosec // see above
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return newProblem(errTLS, fmt.Sprintf("TLS with %s failed: %v", address, err))
	}
	state := conn.ConnectionState()
	if state.NegotiatedProtocol != alpnProtocol {
		return newProblem(errIncorrectResponse, address+" did not take the protocol "+alpnProtocol)
	}
	if len(state.PeerCertificates) == 0 {
		return newProblem(errIncorrectResponse, address+" sent no certificate")
	}
	cert := state.PeerCertificates[0]

	// For exactly this name, and nothing else.
	var only bool
	if ip != nil {
		only = len(cert.IPAddresses) == 1 && cert.IPAddresses[0].Equal(ip) && len(cert.DNSNames) == 0
	} else {
		only = len(cert.DNSNames) == 1 && strings.EqualFold(cert.DNSNames[0], name) && len(cert.IPAddresses) == 0
	}
	if !only || len(cert.EmailAddresses)+len(cert.URIs) != 0 {
		return newProblem(errIncorrectResponse, fmt.Sprintf("the certificate of %s must name %s and nothing else", address, name))
	}
	want := sha256.Sum256([]byte(keyAuth))
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(idPeAcmeIdentifier) {
			continue
		}
		if !ext.Critical {
			return newProblem(errIncorrectResponse, "the acmeIdentifier extension must be critical")
		}
		var got []byte
		if rest, err := asn1.Unmarshal(ext.Value, &got); err != nil || len(rest) != 0 {
			return newProblem(errIncorrectResponse, "the acmeIdentifier extension is malformed")
		}
		if !bytes.Equal(got, want[:]) {
			return newProblem(errIncorrectResponse, "the acmeIdentifier extension has the wrong value")
		}
		return nil
	}
	return newProblem(errIncorrectResponse, "the certificate of "+address+" has no acmeIdentifier extension")
}

// ReverseName is the name a client sends to ask for the tls-alpn-01
// certificate of an IP address (RFC 8738).
func ReverseName(ip net.IP) string { return reverseName(ip) }

// reverseName is the reverse DNS name of an IP address, e.g.
// "5.0.0.10.in-addr.arpa" for 10.0.0.5.
func reverseName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v4[3], v4[2], v4[1], v4[0])
	}
	const hexDigits = "0123456789abcdef"
	var b strings.Builder
	for i := len(ip) - 1; i >= 0; i-- {
		b.WriteByte(hexDigits[ip[i]&0xf])
		b.WriteByte('.')
		b.WriteByte(hexDigits[ip[i]>>4])
		b.WriteByte('.')
	}
	b.WriteString("ip6.arpa")
	return b.String()
}

// ACMEIdentifierExtension returns the critical acmeIdentifier extension
// of a tls-alpn-01 certificate for a key authorization (RFC 8737).
func ACMEIdentifierExtension(keyAuth string) (pkix.Extension, error) {
	sum := sha256.Sum256([]byte(keyAuth))
	value, err := asn1.Marshal(sum[:])
	return pkix.Extension{Id: idPeAcmeIdentifier, Critical: true, Value: value}, err
}
