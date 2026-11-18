// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/metrics"
	"github.com/bastionxp/bastionxp-ca/internal/policy"
	"github.com/bastionxp/bastionxp-ca/internal/token"
)

// handleSignSSH signs one SSH certificate, for a user or for a host.
func (s *Server) handleSignSSH(w http.ResponseWriter, r *http.Request) {
	// Verifier: who is asking? Here, the holder of a token.
	grant, ok := s.verifyToken(w, r)
	if !ok {
		return
	}

	// Template: the token says which kind of certificate it is for.
	template, ok := s.ca.SSHTemplate(grant.Template)
	if !ok {
		writeError(w, http.StatusForbidden, fmt.Sprintf("this token is for %q certificates, which this endpoint does not issue", grant.Template))
		return
	}

	var body api.SignSSHRequest
	if !readJSON(w, r, &body) {
		return
	}
	publicKey, err := parseSSHPublicKey(body.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	validity, err := parseValidity(body.Validity)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Policy: may the holder of this token have these principals?
	// Asking for none means "all the token allows".
	principals := body.Principals
	if len(principals) == 0 {
		principals = grant.Names
	}
	if err := policy.CheckSSH(grant.Names, principals); err != nil {
		s.log.Warn("request refused", "error", err, "token_id", grant.ID, "remote", r.RemoteAddr)
		s.metrics.Refused(metrics.RefusedPolicy)
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	if !s.checkKey(w, r, grant, ca.SSHFingerprint(publicKey)) {
		return
	}

	if !s.useToken(w, r, grant) {
		return
	}

	// CA: sign.
	cert, err := s.ca.IssueSSH(ca.SSHRequest{
		Template:   template,
		PublicKey:  publicKey,
		KeyID:      sshKeyID(grant),
		Principals: principals,
		Validity:   validity,
	})
	if err != nil {
		// IssueSSH refuses requests that are not sound: weak key,
		// validity above the maximum.
		s.log.Warn("certificate not issued", "error", err, "token_id", grant.ID)
		s.metrics.Refused(metrics.RefusedUnsound)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.metrics.Issued(template.Name, verifierName(grant))
	s.log.Info("certificate issued",
		"profile", template.Name,
		"serial", cert.Serial,
		"key_id", cert.KeyId,
		"principals", cert.ValidPrincipals,
		"not_after", time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.RFC3339),
		"verifier", verifierName(grant),
		"subject", grant.Subject,
		"created_by", grant.CreatedBy,
		"token_id", grant.ID,
		"remote", r.RemoteAddr,
	)
	writeJSON(w, http.StatusCreated, api.SignSSHResponse{
		Certificate: string(ssh.MarshalAuthorizedKey(cert)),
	})
}

// sshKeyID builds the key ID of a certificate: "<subject>-<token ID>".
//
// The key ID is what an SSH server writes to its log at each login. The
// subject says who logged in, also when several people share one login
// name. The token ID makes it unique for each certificate, so a login can
// be matched to one line in the CA's log.
//
// Both parts come from the token. The requester must not be able to
// choose the name that shows up in the logs.
func sshKeyID(grant *token.Grant) string {
	return grant.Subject + "-" + grant.ID
}

// parseSSHPublicKey reads one SSH public key line, as found in an
// id_ed25519.pub file.
func parseSSHPublicKey(line string) (ssh.PublicKey, error) {
	if line == "" {
		return nil, errors.New(`"public_key" is required: an SSH public key such as the content of id_ed25519.pub`)
	}
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, errors.New(`"public_key" is not an SSH public key`)
	}
	return publicKey, nil
}
