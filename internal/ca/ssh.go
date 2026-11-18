// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHRequest is everything the CA needs to issue one SSH certificate.
//
// The CA signs exactly what is asked for. The caller must already have
// checked that the requester is allowed to have these principals.
type SSHRequest struct {
	Template  SSHTemplate
	PublicKey ssh.PublicKey // the key the certificate is for

	// KeyID identifies the certificate in the SSH server's logs,
	// e.g. the user's email address or the host name.
	KeyID string

	// Principals are the names the certificate is valid for: login names
	// for a user certificate, host names for a host certificate.
	Principals []string

	// Validity is how long the certificate is valid.
	// Zero means "use the template's default".
	Validity time.Duration
}

// IssueSSH signs an SSH certificate with the user CA key or the host CA key,
// depending on the template.
func (c *CA) IssueSSH(req SSHRequest) (*ssh.Certificate, error) {
	if err := checkSSHRequest(req); err != nil {
		return nil, fmt.Errorf("%s certificate: %w", req.Template.Name, err)
	}
	validity, err := chooseValidity(req.Validity, req.Template.DefaultValidity, req.Template.MaxValidity)
	if err != nil {
		return nil, fmt.Errorf("%s certificate: %w", req.Template.Name, err)
	}

	var signer ssh.Signer
	switch req.Template.CertType {
	case ssh.UserCert:
		signer = c.sshUserCA
	case ssh.HostCert:
		signer = c.sshHostCA
	default:
		return nil, fmt.Errorf("%s certificate: unknown SSH certificate type %d", req.Template.Name, req.Template.CertType)
	}

	serial, err := newSSHSerial()
	if err != nil {
		return nil, err
	}

	now := c.now()
	cert := &ssh.Certificate{
		Key:             req.PublicKey,
		Serial:          serial,
		CertType:        req.Template.CertType,
		KeyId:           req.KeyID,
		ValidPrincipals: req.Principals,
		ValidAfter:      uint64(now.Add(-backdate).Unix()),
		ValidBefore:     uint64(now.Add(validity).Unix()),
		Permissions: ssh.Permissions{
			Extensions:      copyMap(req.Template.Extensions),
			CriticalOptions: copyMap(req.Template.CriticalOptions),
		},
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, fmt.Errorf("sign %s certificate: %w", req.Template.Name, err)
	}
	if c.recorder != nil {
		if err := c.recorder.RecordSSH(cert, req.Template.Name); err != nil {
			return nil, fmt.Errorf("%s certificate: cannot record it, so it is not issued: %w", req.Template.Name, err)
		}
	}
	return cert, nil
}

func checkSSHRequest(req SSHRequest) error {
	if req.Template.Name == "" {
		return errors.New("no template given")
	}
	if req.PublicKey == nil {
		return errors.New("no public key given")
	}
	if err := checkSSHPublicKey(req.PublicKey); err != nil {
		return err
	}
	if req.KeyID == "" {
		return errors.New("a key ID is required")
	}
	// An SSH certificate without principals is valid for every user or
	// host, so never issue one.
	if len(req.Principals) == 0 {
		return errors.New("at least one principal is required")
	}
	for _, principal := range req.Principals {
		if principal == "" {
			return errors.New("empty principal")
		}
	}
	return nil
}

// checkSSHPublicKey rejects SSH keys that are too weak or of a type the CA
// does not sign.
func checkSSHPublicKey(pub ssh.PublicKey) error {
	// A certificate is also an ssh.PublicKey. Signing one would make a
	// certificate for a certificate, which nothing can use.
	if _, isCert := pub.(*ssh.Certificate); isCert {
		return errors.New("the public key is an SSH certificate, give the plain public key")
	}

	switch pub.Type() {
	case ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
		// Keys on a hardware security key (FIDO). Their type fixes
		// their strength, so there is nothing more to check.
		return nil
	}

	// All other key types can be looked at as a standard Go key, and the
	// rules are then the same as for X.509 certificates.
	standard, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return fmt.Errorf("unsupported SSH key type %q", pub.Type())
	}
	return checkPublicKey(standard.CryptoPublicKey())
}

func newSSHSerial() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}

func copyMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
