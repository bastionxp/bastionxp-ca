// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package api defines the JSON messages of the CA's HTTP API.
//
// The server and the client both use these types, so the two cannot
// drift apart.
package api

import "time"

// Paths of the API endpoints.
const (
	HealthPath   = "/health"
	SignX509Path = "/v1/x509/sign"
	SignSSHPath  = "/v1/ssh/sign"

	RenewX509Path = "/v1/x509/renew"
	RenewSSHPath  = "/v1/ssh/renew"

	// The two login paths are visited by a person's browser, not called
	// with JSON. See the Login* and Result* names below.
	OIDCLoginPath    = "/v1/oidc/login"
	OIDCCallbackPath = "/v1/oidc/callback"

	// LDAPLoginPath takes a username and password, checks them against
	// the company's directory and answers with a one-time token.
	LDAPLoginPath = "/v1/ldap/login"
)

// LDAPLoginRequest is the body of POST /v1/ldap/login.
type LDAPLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// What the token is for, as with a browser login: the template, the
	// names, the subject (admins only) and how long the token lasts.
	Template string `json:"profile"`
	// Kind is "ssh" or "x509" when Template is empty: the certificate
	// the directory login gives people for themselves.
	Kind     string   `json:"kind,omitempty"`
	Names    []string `json:"names,omitempty"`
	Subject  string   `json:"subject,omitempty"`
	ValidFor string   `json:"valid_for,omitempty"`
	// Key is the fingerprint of the public key the certificate is for.
	// If given, the token works for that key only, and for one minute.
	Key string `json:"key,omitempty"`
}

// LoginResponse is the answer to POST /v1/ldap/login.
type LoginResponse struct {
	// Token is a one-time token for the sign endpoints.
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

// SignX509Request is the body of POST /v1/x509/sign.
type SignX509Request struct {
	// CSR is the certificate signing request in PEM format.
	CSR string `json:"csr"`
	// Validity is how long the certificate should be valid, e.g. "24h".
	// Empty means the template's default.
	Validity string `json:"validity,omitempty"`
}

// SignX509Response is the answer to POST /v1/x509/sign.
type SignX509Response struct {
	// Certificate is the new certificate in PEM format.
	Certificate string `json:"certificate"`
	// Chain is the new certificate followed by the intermediate CA
	// certificate, in PEM format. This is what a TLS server needs.
	Chain string `json:"chain"`
}

// SignSSHRequest is the body of POST /v1/ssh/sign.
type SignSSHRequest struct {
	// PublicKey is the SSH public key to certify, as one line in the
	// format of an id_ed25519.pub file: "ssh-ed25519 AAAA... comment".
	PublicKey string `json:"public_key"`
	// Principals are the names the certificate should be valid for: login
	// names for a user certificate, host names for a host certificate.
	// Empty means all the names the token allows.
	Principals []string `json:"principals,omitempty"`
	// Validity is how long the certificate should be valid, e.g. "8h".
	// Empty means the template's default.
	Validity string `json:"validity,omitempty"`
}

// SignSSHResponse is the answer to POST /v1/ssh/sign.
type SignSSHResponse struct {
	// Certificate is the new SSH certificate as one line, in the format
	// of an id_ed25519-cert.pub file.
	Certificate string `json:"certificate"`
}

// Query parameters of GET /v1/oidc/login. The program that wants a
// certificate builds this address and opens it in the person's browser.
const (
	// LoginCallback is the address on the person's own machine where
	// the result goes. It must be http://127.0.0.1:<port>/...
	LoginCallback = "callback"
	// LoginState is a random value that is sent back with the result.
	LoginState = "state"
	// LoginProfile is the certificate profile, e.g. "ssh-user".
	LoginProfile = "profile"
	// LoginKind is "ssh" or "x509" when LoginProfile is left out: the
	// certificate the login gives people for themselves, with the
	// profile the CA configures for this login.
	LoginKind = "kind"
	// LoginName is a name the certificate may contain. It can be given
	// several times, and left out for an SSH user certificate for
	// yourself.
	LoginName = "name"
	// LoginSubject says who the token is for. Admins only.
	LoginSubject = "subject"
	// LoginValidFor is how long the token can be used, e.g. "10m".
	LoginValidFor = "valid_for"
	// LoginKey is the fingerprint of the public key the certificate is
	// for. The token then works for that key only.
	LoginKey = "key"
)

// Query parameters of the result, which the CA sends to the callback
// address at the end of a login.
const (
	// ResultToken is the one-time token. Set if the login succeeded.
	ResultToken = "token"
	// ResultError says what went wrong. Set if it did not.
	ResultError = "error"
	// ResultState is the LoginState value, unchanged.
	ResultState = "state"
)

// RenewX509Request is the body of POST /v1/x509/renew. The names are
// not in it: a renewed certificate always gets the names of the old one.
type RenewX509Request struct {
	// CSR is a certificate signing request for the new key, in PEM
	// format. Its names are ignored.
	CSR string `json:"csr"`
}

// RenewSSHRequest is the body of POST /v1/ssh/renew. It is empty: the
// new certificate is for the same host key, with the same principals.
type RenewSSHRequest struct{}

// A renewal proof is the bearer token of a renew request. It is a JWT
// signed with the private key of the certificate that is being renewed,
// and it carries that certificate in its header: an X.509 certificate in
// the standard "x5c" header, an SSH certificate in ProofSSHCertHeader.
// So the server can check that the sender holds the key, not just a copy
// of the public certificate.
const (
	// ProofAudienceX509 and ProofAudienceSSH are the "aud" of a proof.
	// A proof for one kind of renewal does not work for the other.
	ProofAudienceX509 = "bastionxp-ca:renew:x509"
	ProofAudienceSSH  = "bastionxp-ca:renew:ssh"
	// ProofSSHCertHeader holds the SSH certificate, as one line in the
	// format of an id_ed25519-cert.pub file.
	ProofSSHCertHeader = "bastionxp-ca-ssh-cert"
	// ProofMaxLifetime is the longest a proof may be valid.
	ProofMaxLifetime = 5 * time.Minute
)

// ProofClaims are the claims of a renewal proof besides the standard ones
// (aud, exp, iat, jti).
type ProofClaims struct {
	// BodySHA256 is the SHA-256 of the request body, in URL-safe
	// base64. It ties the proof to this one request.
	BodySHA256 string `json:"body_sha256"`
}

// Error is the body of every response that is not a success.
type Error struct {
	Error string `json:"error"`
}
