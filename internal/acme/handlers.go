// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// ---- What the server sends: the JSON forms of RFC 8555 ----

type directoryJSON struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	KeyChange  string `json:"keyChange"`
	RevokeCert string `json:"revokeCert"`
	// RenewalInfo is RFC 9773's endpoint.
	RenewalInfo string `json:"renewalInfo"`
}

type accountJSON struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
}

type identifierJSON struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type orderJSON struct {
	Status         string           `json:"status"`
	Expires        string           `json:"expires"`
	Identifiers    []identifierJSON `json:"identifiers"`
	Authorizations []string         `json:"authorizations"`
	Finalize       string           `json:"finalize"`
	Certificate    string           `json:"certificate,omitempty"`
	// Replaces is RFC 9773's: the certificate this order renews.
	Replaces string `json:"replaces,omitempty"`
}

type authzJSON struct {
	Status     string          `json:"status"`
	Expires    string          `json:"expires"`
	Identifier identifierJSON  `json:"identifier"`
	Challenges []challengeJSON `json:"challenges"`
	// Wildcard is set for "*.example.com"; the identifier is then
	// "example.com" (RFC 8555, section 7.1.4).
	Wildcard bool `json:"wildcard,omitempty"`
}

type challengeJSON struct {
	Type   string   `json:"type"`
	URL    string   `json:"url"`
	Token  string   `json:"token"`
	Status string   `json:"status"`
	Error  *problem `json:"error,omitempty"`
}

// ---- Directory and nonce: no signature needed ----

// handleDirectory tells a client where the other endpoints are.
func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	base := s.baseURL(r)
	s.writeJSON(w, r, http.StatusOK, directoryJSON{
		NewNonce:    base + "/acme/new-nonce",
		NewAccount:  base + "/acme/new-account",
		NewOrder:    base + "/acme/new-order",
		KeyChange:   base + "/acme/key-change",
		RevokeCert:  base + "/acme/revoke-cert",
		RenewalInfo: base + RenewalInfoPath,
	})
}

// handleNewNonce gives a client its first nonce. The nonce is in a
// header, which addCommonHeaders sets; there is no body.
func (s *Server) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	s.addCommonHeaders(w, r)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Step 1: the account ----

// handleNewAccount creates an account for the key that signed the
// request, or finds the one that key has already.
func (s *Server) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	req, ok := s.readSigned(w, r, keyInRequest)
	if !ok {
		return
	}
	var body struct {
		Contact            []string `json:"contact"`
		OnlyReturnExisting bool     `json:"onlyReturnExisting"`
	}
	if err := req.decode(&body); err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "invalid new-account request: "+err.Error())
		return
	}
	if len(body.Contact) > 10 {
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "too many contacts")
		return
	}
	for _, contact := range body.Contact {
		if len(contact) > 256 {
			s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "a contact is too long")
			return
		}
	}

	keyPrint, err := thumbprint(req.key)
	if err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, errBadPublicKey, "the account key cannot be used")
		return
	}

	// A client that has lost its account address asks for it this way.
	if body.OnlyReturnExisting {
		account, err := s.store.ACMEAccountByThumbprint(r.Context(), keyPrint)
		if errors.Is(err, store.ErrNotFound) {
			s.writeProblem(w, r, http.StatusBadRequest, errAccountDoesNotExist, "there is no account for this key")
			return
		}
		if err != nil {
			s.writeInternalError(w, r, "cannot read account", err)
			return
		}
		if account.Status == store.ACMEAccountDeactivated {
			s.writeProblem(w, r, http.StatusUnauthorized, errUnauthorized, "the account of this key was deactivated")
			return
		}
		w.Header().Set("Location", s.accountURL(r, account.ID))
		s.writeJSON(w, r, http.StatusOK, accountJSON{Status: account.Status, Contact: account.Contact})
		return
	}

	// Limit: new accounts per address.
	remote := hostOf(r.RemoteAddr)
	if full, retry := s.accountsPerIP.full(remote); full {
		s.rateLimited(w, r, retry, "too many new accounts from this address")
		return
	}

	id, err := randomID()
	if err != nil {
		s.writeInternalError(w, r, "cannot create an ID", err)
		return
	}
	jwk, err := req.key.MarshalJSON()
	if err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, errBadPublicKey, "the account key cannot be used")
		return
	}
	account, created, err := s.store.CreateACMEAccount(r.Context(), store.ACMEAccount{
		ID: id, Thumbprint: keyPrint, JWK: string(jwk), Contact: body.Contact,
	})
	if err != nil {
		s.writeInternalError(w, r, "cannot create account", err)
		return
	}
	// A closed account's key cannot open it again, nor a new one.
	if account.Status == store.ACMEAccountDeactivated {
		s.writeProblem(w, r, http.StatusUnauthorized, errUnauthorized, "the account of this key was deactivated: use a new key")
		return
	}

	w.Header().Set("Location", s.accountURL(r, account.ID))
	status := http.StatusOK // the key had an account already
	if created {
		s.accountsPerIP.add(remote)
		status = http.StatusCreated
		s.log.Info("ACME account created", "acme_account", account.ID, "contact", account.Contact, "remote", r.RemoteAddr)
	}
	s.writeJSON(w, r, status, accountJSON{Status: "valid", Contact: account.Contact})
}

// ---- Step 2: the order ----

// handleNewOrder creates an order for a list of host names, with one
// authorization for each name.
func (s *Server) handleNewOrder(w http.ResponseWriter, r *http.Request, req *request) {
	var body struct {
		Identifiers []identifierJSON `json:"identifiers"`
		// Replaces names the certificate this order renews (RFC 9773).
		Replaces string `json:"replaces"`
	}
	if err := req.decode(&body); err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "invalid new-order request: "+err.Error())
		return
	}
	if len(body.Identifiers) == 0 {
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "the order names no identifiers")
		return
	}
	if len(body.Identifiers) > maxNamesPerOrder {
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "the order has too many identifiers")
		return
	}
	// Limit: new orders per account.
	if full, retry := s.ordersPerAccount.full(req.account.ID); full {
		s.rateLimited(w, r, retry, "too many new orders for this account")
		return
	}

	// Policy: may an ACME client have a certificate for these names?
	// The rules as they are now, for the whole order.
	rules := s.rules.Load()
	var names []string
	seen := make(map[string]bool)
	for _, identifier := range body.Identifiers {
		var name string
		var err error
		switch identifier.Type {
		case "dns":
			name = strings.ToLower(identifier.Value)
			err = rules.CheckDomain(name)
		case "ip":
			// RFC 8738. Kept in its plain form, which is also how a
			// certificate shows it.
			ip := net.ParseIP(identifier.Value)
			if ip == nil {
				s.writeProblem(w, r, http.StatusBadRequest, errMalformed, `"`+identifier.Value+`" is not an IP address`)
				return
			}
			name = ip.String()
			err = rules.CheckIP(ip)
		default:
			s.writeProblem(w, r, http.StatusBadRequest, errUnsupportedIdentifier,
				`only identifiers of type "dns" and "ip" are supported, not "`+identifier.Type+`"`)
			return
		}
		if err != nil {
			s.log.Warn("ACME order refused", "error", err, "acme_account", req.account.ID, "remote", r.RemoteAddr)
			s.writeProblem(w, r, http.StatusBadRequest, errRejectedIdentifier, err.Error())
			return
		}
		// A name no allowed challenge can prove: say so now, not with
		// an authorization nobody can complete.
		if len(s.challengesFor(name)) == 0 {
			detail := "no challenge this CA offers can prove " + name
			if isWildcard(name) {
				detail = "wildcard names need dns-01, which this CA does not offer"
			}
			s.log.Warn("ACME order refused", "error", detail, "acme_account", req.account.ID, "remote", r.RemoteAddr)
			s.writeProblem(w, r, http.StatusBadRequest, errRejectedIdentifier, detail)
			return
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}

	if body.Replaces != "" && !s.checkReplaces(w, r, body.Replaces, req.account.ID, names) {
		return
	}

	orderID, err := randomID()
	if err != nil {
		s.writeInternalError(w, r, "cannot create an ID", err)
		return
	}
	expires := time.Now().Add(orderLifetime)
	order := store.ACMEOrder{ID: orderID, AccountID: req.account.ID, Names: names, Replaces: body.Replaces, Expires: expires}
	var authzs []store.ACMEAuthz
	for _, name := range names {
		authzID, err := randomID()
		if err != nil {
			s.writeInternalError(w, r, "cannot create an ID", err)
			return
		}
		token, err := randomID()
		if err != nil {
			s.writeInternalError(w, r, "cannot create a token", err)
			return
		}
		authzs = append(authzs, store.ACMEAuthz{ID: authzID, Name: name, Token: token, Expires: expires})
	}
	s.ordersPerAccount.add(req.account.ID)
	err = s.store.CreateACMEOrder(r.Context(), order, authzs)
	if errors.Is(err, store.ErrAlreadyReplaced) {
		s.writeProblem(w, r, http.StatusConflict, errAlreadyReplaced, "replaces: another order has already replaced this certificate")
		return
	}
	if err != nil {
		s.writeInternalError(w, r, "cannot create order", err)
		return
	}

	s.writeOrder(w, r, http.StatusCreated, &order)
}

// handleOrder shows a client one of its orders.
func (s *Server) handleOrder(w http.ResponseWriter, r *http.Request, req *request) {
	order, ok := s.ownOrder(w, r, req)
	if !ok {
		return
	}
	s.writeOrder(w, r, http.StatusOK, order)
}

// ownOrder loads the order named in the address and makes sure it
// belongs to the account that signed the request.
func (s *Server) ownOrder(w http.ResponseWriter, r *http.Request, req *request) (*store.ACMEOrder, bool) {
	order, err := s.store.ACMEOrder(r.Context(), r.PathValue("id"))
	// An order of another account is "not found" as well: do not tell
	// a client which IDs exist.
	if errors.Is(err, store.ErrNotFound) || (err == nil && order.AccountID != req.account.ID) {
		s.writeProblem(w, r, http.StatusNotFound, errMalformed, "no such order")
		return nil, false
	}
	if err != nil {
		s.writeInternalError(w, r, "cannot read order", err)
		return nil, false
	}
	return order, true
}

// writeOrder sends an order to the client.
func (s *Server) writeOrder(w http.ResponseWriter, r *http.Request, status int, order *store.ACMEOrder) {
	authzs, err := s.store.ACMEAuthzsOfOrder(r.Context(), order.ID)
	if err != nil {
		s.writeInternalError(w, r, "cannot read authorizations", err)
		return
	}
	body := orderJSON{
		Status:   order.Status(authzs),
		Expires:  order.Expires.UTC().Format(time.RFC3339),
		Finalize: s.orderURL(r, order.ID) + "/finalize",
	}
	for _, name := range order.Names {
		body.Identifiers = append(body.Identifiers, identifierOf(name))
	}
	for _, authz := range authzs {
		body.Authorizations = append(body.Authorizations, s.authzURL(r, authz.ID))
	}
	if order.Certificate != "" {
		body.Certificate = s.certificateURL(r, order.ID)
	}
	body.Replaces = order.Replaces
	w.Header().Set("Location", s.orderURL(r, order.ID))
	s.writeJSON(w, r, status, body)
}

// ---- Steps 3 and 4: authorization and challenge ----

// handleAuthz shows a client one of its authorizations, with the
// challenge it has to answer.
func (s *Server) handleAuthz(w http.ResponseWriter, r *http.Request, req *request) {
	authz, ok := s.ownAuthz(w, r, req)
	if !ok {
		return
	}
	s.writeJSON(w, r, http.StatusOK, authzJSON{
		Status:     authz.Status,
		Expires:    authz.Expires.UTC().Format(time.RFC3339),
		Identifier: identifierOf(strings.TrimPrefix(authz.Name, "*.")),
		Challenges: s.challengesOf(r, authz),
		Wildcard:   isWildcard(authz.Name),
	})
}

// ownAuthz loads the authorization named in the address and makes sure
// it belongs to the account that signed the request.
func (s *Server) ownAuthz(w http.ResponseWriter, r *http.Request, req *request) (*store.ACMEAuthz, bool) {
	authz, err := s.store.ACMEAuthz(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && authz.AccountID != req.account.ID) {
		s.writeProblem(w, r, http.StatusNotFound, errMalformed, "no such authorization")
		return nil, false
	}
	if err != nil {
		s.writeInternalError(w, r, "cannot read authorization", err)
		return nil, false
	}
	return authz, true
}

// challengesOf returns the challenges of an authorization.
func (s *Server) challengesOf(r *http.Request, authz *store.ACMEAuthz) []challengeJSON {
	var challenges []challengeJSON
	for _, c := range s.challengesFor(authz.Name) {
		challenges = append(challenges, s.challengeOf(r, authz, c))
	}
	return challenges
}

// challengeOf returns one challenge of an authorization. The one that
// decided the authorization has its status; the others stay pending, and
// can no longer be used once the authorization is decided.
func (s *Server) challengeOf(r *http.Request, authz *store.ACMEAuthz, kind string) challengeJSON {
	challenge := challengeJSON{
		Type:   kind,
		URL:    s.challengeURL(r, authz.ID, kind),
		Token:  authz.Token,
		Status: store.ACMEPending,
	}
	if authz.Challenge != kind {
		return challenge
	}
	challenge.Status = authz.Status
	if authz.Status == store.ACMEInvalid && authz.Error != "" {
		var p problem
		if json.Unmarshal([]byte(authz.Error), &p) == nil {
			challenge.Error = &p
		}
	}
	return challenge
}

// handleChallenge is called by a client that says: "the answer is in
// place, come and look". The server looks right away, and the answer to
// this request already says how it went.
func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request, req *request) {
	authz, ok := s.ownAuthz(w, r, req)
	if !ok {
		return
	}
	kind := r.PathValue("type")
	if !s.offers(authz.Name, kind) {
		s.writeProblem(w, r, http.StatusNotFound, errMalformed, "no such challenge")
		return
	}

	// A request without content only asks for the current state. One
	// with content ("{}") asks for the check. An authorization that is
	// decided stays as it is.
	if len(req.payload) > 0 && authz.Status == store.ACMEPending {
		keyPrint, err := thumbprint(req.key)
		if err != nil {
			s.writeInternalError(w, r, "cannot fingerprint account key", err)
			return
		}
		// Verifier: does the client control the host name?
		newStatus, errText := store.ACMEValid, ""
		if failure := s.check(r.Context(), kind, authz.Name, authz.Token, authz.Token+"."+keyPrint); failure != nil {
			newStatus = store.ACMEInvalid
			encoded, _ := json.Marshal(failure)
			errText = string(encoded)
			s.log.Warn("ACME challenge failed", "name", authz.Name, "challenge", kind, "detail", failure.Detail, "acme_account", req.account.ID)
		}
		if _, err := s.store.FinishACMEAuthz(r.Context(), authz.ID, newStatus, kind, errText); err != nil {
			s.writeInternalError(w, r, "cannot save authorization", err)
			return
		}
		// Read it back: another request may have decided it first.
		authz, err = s.store.ACMEAuthz(r.Context(), authz.ID)
		if err != nil {
			s.writeInternalError(w, r, "cannot read authorization", err)
			return
		}
	}

	w.Header().Add("Link", "<"+s.authzURL(r, authz.ID)+`>;rel="up"`)
	s.writeJSON(w, r, http.StatusOK, s.challengeOf(r, authz, kind))
}

// ---- Step 5: finalize and download ----

// handleFinalize takes the CSR for an order whose names are all proved,
// and has the CA sign the certificate.
func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request, req *request) {
	order, ok := s.ownOrder(w, r, req)
	if !ok {
		return
	}
	authzs, err := s.store.ACMEAuthzsOfOrder(r.Context(), order.ID)
	if err != nil {
		s.writeInternalError(w, r, "cannot read authorizations", err)
		return
	}
	switch order.Status(authzs) {
	case "ready":
		// Go on.
	case "valid":
		// The certificate exists already. Do not issue a second one.
		s.writeOrder(w, r, http.StatusOK, order)
		return
	default:
		s.writeProblem(w, r, http.StatusForbidden, errOrderNotReady, "the order is not ready: not all names have been proved")
		return
	}

	var body struct {
		CSR string `json:"csr"` // DER, in URL-safe base64
	}
	if err := req.decode(&body); err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, errMalformed, "invalid finalize request: "+err.Error())
		return
	}
	der, err := base64.RawURLEncoding.DecodeString(body.CSR)
	if err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, errBadCSR, `"csr" is not URL-safe base64`)
		return
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, errBadCSR, "cannot read the CSR")
		return
	}

	// Policy: the certificate may contain exactly the names that were
	// proved for this order. Not fewer, and above all not more.
	if err := checkCSRNames(csr, order.Names); err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, errBadCSR, err.Error())
		return
	}
	// An account key signs requests and should do nothing else: no
	// certificate may carry this account's key, nor any other account's
	// (RFC 8555, section 11.1).
	if sameKey(csr.PublicKey, req.key.Key) {
		s.writeProblem(w, r, http.StatusBadRequest, errBadCSR, "the certificate must not use the account key")
		return
	}
	if keyPrint, err := thumbprint(&jose.JSONWebKey{Key: csr.PublicKey}); err == nil {
		_, err := s.store.ACMEAccountByThumbprint(r.Context(), keyPrint)
		if err == nil {
			s.writeProblem(w, r, http.StatusBadRequest, errBadCSR, "the certificate must not use the key of an ACME account")
			return
		}
		if !errors.Is(err, store.ErrNotFound) {
			s.writeInternalError(w, r, "cannot read account", err)
			return
		}
	}

	// CA: sign. RequestFromCSR checks the CSR's signature.
	x509Req, err := ca.RequestFromCSR(s.profile, csr)
	if err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, errBadCSR, err.Error())
		return
	}
	x509Req.Protocol = ca.ProtocolACME
	cert, err := s.ca.IssueX509(x509Req)
	if err != nil {
		// IssueX509 refuses requests that are not sound, e.g. a weak key.
		s.writeProblem(w, r, http.StatusBadRequest, errBadCSR, err.Error())
		return
	}
	chain := string(ca.EncodeCertPEM(append([]*x509.Certificate{cert}, s.ca.Chain()...)...))
	if err := s.store.SetACMEOrderCertificate(r.Context(), order.ID, store.X509Serial(cert.SerialNumber), chain); err != nil {
		s.writeInternalError(w, r, "cannot save certificate", err)
		return
	}
	order.Certificate = chain

	s.metrics.Issued(s.profile.Name, "acme")
	s.log.Info("certificate issued",
		"profile", s.profile.Name,
		"serial", cert.SerialNumber.Text(16),
		"common_name", cert.Subject.CommonName,
		"dns_names", cert.DNSNames,
		"not_after", cert.NotAfter.UTC().Format(time.RFC3339),
		"verifier", "acme",
		"acme_account", req.account.ID,
		"acme_order", order.ID,
		"remote", r.RemoteAddr,
	)
	s.writeOrder(w, r, http.StatusOK, order)
}

// checkCSRNames makes sure the CSR asks for exactly the names of the
// order, and for nothing else that would end up in the certificate.
func checkCSRNames(csr *x509.CertificateRequest, orderNames []string) error {
	if len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 {
		return errors.New("the CSR may only contain DNS names and IP addresses")
	}
	var csrNames []string
	seen := make(map[string]bool)
	add := func(name string) {
		if ip := net.ParseIP(name); ip != nil {
			name = ip.String()
		}
		name = strings.ToLower(name)
		if name != "" && !seen[name] {
			seen[name] = true
			csrNames = append(csrNames, name)
		}
	}
	add(csr.Subject.CommonName)
	for _, name := range csr.DNSNames {
		add(name)
	}
	for _, ip := range csr.IPAddresses {
		add(ip.String())
	}

	want := append([]string(nil), orderNames...)
	sort.Strings(want)
	sort.Strings(csrNames)
	if strings.Join(csrNames, ",") != strings.Join(want, ",") {
		return errors.New("the names in the CSR (" + strings.Join(csrNames, ", ") +
			") are not the names of the order (" + strings.Join(want, ", ") + ")")
	}
	// Every name must be in the list TLS clients really check, as a DNS
	// name or an IP address according to its kind.
	if len(csr.DNSNames)+len(csr.IPAddresses) != len(want) {
		return errors.New("every name of the order must be a subject alternative name in the CSR: a DNS name, or an IP address")
	}
	for _, name := range csr.DNSNames {
		if net.ParseIP(name) != nil {
			return errors.New("an IP address must be an IP address in the CSR, not a DNS name")
		}
	}
	return nil
}

// identifierOf is the ACME identifier of a stored name.
func identifierOf(name string) identifierJSON {
	if net.ParseIP(name) != nil {
		return identifierJSON{Type: "ip", Value: name}
	}
	return identifierJSON{Type: "dns", Value: name}
}

// sameKey reports whether two public keys are the same key.
func sameKey(a, b crypto.PublicKey) bool {
	type equaler interface {
		Equal(crypto.PublicKey) bool
	}
	ka, ok := a.(equaler)
	return ok && ka.Equal(b)
}

// handleCertificate lets a client download the certificate of one of
// its orders: the certificate followed by the intermediate, as PEM.
func (s *Server) handleCertificate(w http.ResponseWriter, r *http.Request, req *request) {
	order, ok := s.ownOrder(w, r, req)
	if !ok {
		return
	}
	if order.Certificate == "" {
		s.writeProblem(w, r, http.StatusNotFound, errMalformed, "this order has no certificate yet")
		return
	}
	s.addCommonHeaders(w, r)
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(order.Certificate))
}
