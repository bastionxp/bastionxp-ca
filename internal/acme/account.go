// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-jose/go-jose/v4"

	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// What a client can do with its account besides orders: see it, give it
// a new key (RFC 8555, section 7.3.5) and close it (section 7.3.6).
// Changing contacts is not supported.

// handleAccount shows a client its own account, or closes it.
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request, req *request) {
	if r.PathValue("id") != req.account.ID {
		s.writeProblem(w, r, http.StatusForbidden, errUnauthorized, "this is not your account")
		return
	}
	if len(req.payload) > 0 && string(req.payload) != "{}" {
		var body struct {
			Status  string          `json:"status"`
			Contact json.RawMessage `json:"contact"`
		}
		if err := req.decode(&body); err != nil {
			s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "invalid account update: "+err.Error())
			return
		}
		// Changing contacts is not supported. Say so instead of
		// pretending that it worked.
		if body.Contact != nil {
			s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "this server does not support changing an account's contacts")
			return
		}
		switch body.Status {
		case "", store.ACMEAccountValid:
			// Nothing to change.
		case store.ACMEAccountDeactivated:
			if err := s.store.DeactivateACMEAccount(r.Context(), req.account.ID); err != nil {
				s.writeInternalError(w, r, "cannot deactivate the account", err)
				return
			}
			s.log.Info("ACME account deactivated", "acme_account", req.account.ID, "remote", r.RemoteAddr)
			s.writeJSON(w, r, http.StatusOK, accountJSON{Status: store.ACMEAccountDeactivated, Contact: req.account.Contact})
			return
		default:
			s.writeProblem(w, r, http.StatusBadRequest, errMalformed, `an account's status can only be changed to "deactivated"`)
			return
		}
	}
	s.writeJSON(w, r, http.StatusOK, accountJSON{Status: req.account.Status, Contact: req.account.Contact})
}

// handleKeyChange gives an account a new key (RFC 8555, section 7.3.5).
// The request is signed with the old key and carries a second request,
// signed with the new key: both keys agree to the change.
func (s *Server) handleKeyChange(w http.ResponseWriter, r *http.Request, req *request) {
	inner, err := jose.ParseSigned(string(req.payload), signatureAlgorithms)
	if err != nil || len(inner.Signatures) != 1 {
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "the key change must carry a request signed with the new key")
		return
	}
	header := inner.Signatures[0].Protected
	newKey := header.JSONWebKey
	if newKey == nil || header.KeyID != "" || !newKey.Valid() || !newKey.IsPublic() {
		s.writeProblem(w, r, http.StatusBadRequest, errBadPublicKey, `the inner request must carry the new public key ("jwk")`)
		return
	}
	payload, err := inner.Verify(newKey)
	if err != nil {
		s.writeProblem(w, r, http.StatusUnauthorized, errUnauthorized, "the inner request is not signed with the new key")
		return
	}
	if url, _ := header.ExtraHeaders[jose.HeaderKey("url")].(string); url != s.baseURL(r)+r.URL.Path {
		s.writeProblem(w, r, http.StatusUnauthorized, errUnauthorized, `the inner request's "url" is not this address`)
		return
	}
	var body struct {
		Account string          `json:"account"`
		OldKey  json.RawMessage `json:"oldKey"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "invalid key change: "+err.Error())
		return
	}
	if body.Account != s.accountURL(r, req.account.ID) {
		s.writeProblem(w, r, http.StatusForbidden, errUnauthorized, "the key change names another account")
		return
	}
	var oldKey jose.JSONWebKey
	if err := json.Unmarshal(body.OldKey, &oldKey); err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, `"oldKey" is not a key`)
		return
	}
	oldPrint, err := thumbprint(&oldKey)
	if err != nil || oldPrint != req.account.Thumbprint {
		s.writeProblem(w, r, http.StatusUnauthorized, errUnauthorized, `"oldKey" is not the account's key`)
		return
	}
	newPrint, err := thumbprint(newKey)
	if err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, errBadPublicKey, "the new key cannot be used")
		return
	}
	jwk, err := newKey.MarshalJSON()
	if err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, errBadPublicKey, "the new key cannot be used")
		return
	}
	err = s.store.ChangeACMEAccountKey(r.Context(), req.account.ID, newPrint, string(jwk))
	if errors.Is(err, store.ErrKeyInUse) {
		if other, err := s.store.ACMEAccountByThumbprint(r.Context(), newPrint); err == nil {
			w.Header().Set("Location", s.accountURL(r, other.ID))
		}
		s.writeProblem(w, r, http.StatusConflict, errMalformed, "the new key belongs to another account")
		return
	}
	if err != nil {
		s.writeInternalError(w, r, "cannot change the key", err)
		return
	}
	s.log.Info("ACME account key changed", "acme_account", req.account.ID, "remote", r.RemoteAddr)
	s.writeJSON(w, r, http.StatusOK, accountJSON{Status: "valid", Contact: req.account.Contact})
}
