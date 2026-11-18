// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/ldap"
	"github.com/bastionxp/bastionxp-ca/internal/metrics"
)

// This file is the LDAP login verifier: a person gives their directory
// username and password (Active Directory, or another LDAP server), the
// CA checks them against the directory, and answers with a one-time token.
// From there the road is the same as after a browser login: the same
// access rules, the same token, the same sign endpoints.
//
// The password passes through the CA on its way to the directory. It is
// never stored or logged, and only ever goes over TLS: to here (HTTPS) and
// from here to the directory (LDAPS or StartTLS). That is why browser login
// (OIDC), where the CA never sees a password, is the better choice where
// the company has an identity provider.

func (s *Server) handleLDAPLogin(w http.ResponseWriter, r *http.Request) {
	if s.ldap == nil || s.access.Load() == nil {
		writeError(w, http.StatusNotFound, "login with a directory password is not set up on this CA")
		return
	}
	// Nothing in front of the CA may keep the answer, which holds a token.
	w.Header().Set("Cache-Control", "no-store")

	var req api.LDAPLoginRequest
	if !readJSON(w, r, &req) {
		return
	}
	var ok bool
	if req.Template, ok = s.ownProfile("ldap", req.Template, req.Kind); !ok {
		writeError(w, http.StatusBadRequest, "the profile must be tls-server, tls-client, tls-device, ssh-user, ssh-host or one configured on the CA")
		return
	}
	var validFor time.Duration
	if req.ValidFor != "" {
		var err error
		if validFor, err = time.ParseDuration(req.ValidFor); err != nil {
			writeError(w, http.StatusBadRequest, `invalid validity for the token: use a duration such as "10m" or "1h"`)
			return
		}
	}

	// Verifier: who is asking? The directory tells us.
	id, err := s.ldap.Login(r.Context(), req.Username, req.Password, r.RemoteAddr)
	switch {
	case errors.Is(err, ldap.ErrLoginFailed):
		s.log.Warn("login failed", "provider", "ldap", "login", req.Username, "remote", r.RemoteAddr)
		s.metrics.Login("ldap", metrics.LoginFailed)
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	case errors.Is(err, ldap.ErrTooManyFailures):
		s.log.Warn("login refused: too many failures", "provider", "ldap", "login", req.Username, "remote", r.RemoteAddr)
		s.metrics.Login("ldap", metrics.LoginTooMany)
		writeError(w, http.StatusTooManyRequests, "too many failed logins, try again in 15 minutes")
		return
	case err != nil:
		s.log.Error("cannot check a login with the directory", "error", err)
		writeError(w, http.StatusBadGateway, "the CA cannot check the login with the directory, try again later")
		return
	}

	oneTime, err := s.tokenFor(id, wantedToken{
		template:       req.Template,
		names:          req.Names,
		subject:        req.Subject,
		validFor:       validFor,
		keyFingerprint: req.Key,
	}, "ldap", r.RemoteAddr)
	var refused refusedError
	if errors.As(err, &refused) {
		writeError(w, http.StatusForbidden, refused.message)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	grant, err := s.tokens.Verify(oneTime)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, api.LoginResponse{Token: oneTime, Expires: grant.Expires})
}
