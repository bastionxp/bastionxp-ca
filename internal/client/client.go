// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package client talks to a BastionXP CA server over its HTTP API.
//
// It is what the client commands (bxp tls, ssh, token) use, and it can be used from
// other Go programs in this module the same way.
package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/api"
)

// maxResponseBytes limits how much of a response is read. Certificates
// are a few kilobytes.
const maxResponseBytes = 1024 * 1024

// Client sends requests to one BastionXP CA server. Create one with New.
type Client struct {
	baseURL string
	http    *http.Client
}

// New returns a client for the server at serverURL, for example
// "https://ca.example.com:8443".
//
// rootFile is the path of the CA's root certificate (root.crt). The client
// trusts the server only if its certificate comes from this root. With an
// empty rootFile the client uses the roots the operating system trusts,
// which only works if the server is behind a publicly trusted certificate.
func New(serverURL, rootFile string) (*Client, error) {
	parsed, err := url.Parse(serverURL)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("invalid server URL %q: use a form like https://ca.example.com:8443", serverURL)
	}
	// Tokens are sent to the server. Without TLS anyone on the network
	// could read and use them.
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("invalid server URL %q: it must start with https://", serverURL)
	}

	httpClient, err := NewHTTPClient(rootFile)
	if err != nil {
		return nil, err
	}
	return &Client{baseURL: strings.TrimRight(serverURL, "/"), http: httpClient}, nil
}

// NewHTTPClient returns an HTTP client that trusts servers whose
// certificate comes from the root certificate in rootFile. With an empty
// rootFile it trusts what the operating system trusts.
func NewHTTPClient(rootFile string) (*http.Client, error) {
	if rootFile == "" {
		return HTTPClientFor(nil), nil
	}
	pemData, err := os.ReadFile(rootFile)
	if err != nil {
		return nil, fmt.Errorf("read root certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("%s contains no PEM certificate", rootFile)
	}
	return HTTPClientFor(pool), nil
}

// HTTPClientFor returns an HTTP client that trusts servers whose
// certificate comes from one of the roots in pool. A nil pool means
// what the operating system trusts.
func HTTPClientFor(roots *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		},
	}
}

// SignX509 asks the server to sign a TLS certificate for the CSR.
func (c *Client) SignX509(ctx context.Context, token string, req api.SignX509Request) (*api.SignX509Response, error) {
	var resp api.SignX509Response
	if err := c.post(ctx, api.SignX509Path, token, req, &resp); err != nil {
		return nil, err
	}
	if resp.Certificate == "" || resp.Chain == "" {
		return nil, errors.New("the server's answer contains no certificate")
	}
	return &resp, nil
}

// SignSSH asks the server to sign an SSH certificate for the public key.
func (c *Client) SignSSH(ctx context.Context, token string, req api.SignSSHRequest) (*api.SignSSHResponse, error) {
	var resp api.SignSSHResponse
	if err := c.post(ctx, api.SignSSHPath, token, req, &resp); err != nil {
		return nil, err
	}
	if resp.Certificate == "" {
		return nil, errors.New("the server's answer contains no certificate")
	}
	return &resp, nil
}

// WithHTTPClient returns a copy of c that uses httpClient. Tests use it
// to reach a test server.
func WithHTTPClient(c *Client, httpClient *http.Client) *Client {
	copied := *c
	copied.http = httpClient
	return &copied
}

// RenewX509 renews a TLS certificate. cert and key are the current
// certificate and its private key; csrPEM is a CSR for the new key.
func (c *Client) RenewX509(ctx context.Context, cert *x509.Certificate, key crypto.Signer, csrPEM string) (*api.SignX509Response, error) {
	body, err := json.Marshal(api.RenewX509Request{CSR: csrPEM})
	if err != nil {
		return nil, err
	}
	proof, err := Proof{Key: key, X509: cert, Body: body}.Sign()
	if err != nil {
		return nil, err
	}
	var resp api.SignX509Response
	if err := c.postBytes(ctx, api.RenewX509Path, proof, body, &resp); err != nil {
		return nil, err
	}
	if resp.Certificate == "" || resp.Chain == "" {
		return nil, errors.New("the server's answer contains no certificate")
	}
	return &resp, nil
}

// RenewSSH renews an SSH host certificate, for the same host key. key
// is the host's private key.
func (c *Client) RenewSSH(ctx context.Context, cert *ssh.Certificate, key crypto.Signer) (*api.SignSSHResponse, error) {
	body, err := json.Marshal(api.RenewSSHRequest{})
	if err != nil {
		return nil, err
	}
	proof, err := Proof{Key: key, SSH: cert, Body: body}.Sign()
	if err != nil {
		return nil, err
	}
	var resp api.SignSSHResponse
	if err := c.postBytes(ctx, api.RenewSSHPath, proof, body, &resp); err != nil {
		return nil, err
	}
	if resp.Certificate == "" {
		return nil, errors.New("the server's answer contains no certificate")
	}
	return &resp, nil
}

// LoginURL returns the address to open in a person's browser to start a
// login: path is api.OIDCLoginPath, query holds
// the api.Login* parameters.
func (c *Client) LoginURL(path string, query url.Values) string {
	return c.baseURL + path + "?" + query.Encode()
}

// LoginIsSetUp asks the server whether it offers the login at path.
func (c *Client) LoginIsSetUp(ctx context.Context, path string) (bool, error) {
	// A request without parameters starts no login. A server with this
	// login complains about the missing parameters (400), one without
	// it says "not found" (404).
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return false, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return false, connectError(c.baseURL, err)
	}
	resp.Body.Close()
	return resp.StatusCode != http.StatusNotFound, nil
}

// post sends body as JSON with the token and decodes the answer into dest.
// An error answer from the server is returned as an error with the
// server's message.
// LDAPLogin checks a directory username and password at the CA and
// returns a one-time token for what req asks for.
func (c *Client) LDAPLogin(ctx context.Context, req api.LDAPLoginRequest) (*api.LoginResponse, error) {
	var resp api.LoginResponse
	if err := c.post(ctx, api.LDAPLoginPath, "", req, &resp); err != nil {
		return nil, err
	}
	if resp.Token == "" {
		return nil, errors.New("the server's answer contains no token")
	}
	return &resp, nil
}

func (c *Client) post(ctx context.Context, path, token string, body, dest any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return c.postBytes(ctx, path, token, data, dest)
}

// postBytes is post with a body that is already JSON. A renewal proof
// covers the exact bytes of the body, so they must not be built twice.
func (c *Client) postBytes(ctx context.Context, path, token string, data []byte, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return connectError(c.baseURL, err)
	}
	defer resp.Body.Close()

	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("read the server's answer: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var apiErr api.Error
		if json.Unmarshal(answer, &apiErr) == nil && apiErr.Error != "" {
			return fmt.Errorf("the CA server refused the request: %s", apiErr.Error)
		}
		// Not an answer from BastionXP CA. Maybe a proxy, or the wrong URL.
		return fmt.Errorf("the CA server answered with status %s", resp.Status)
	}
	if err := json.Unmarshal(answer, dest); err != nil {
		return fmt.Errorf("cannot understand the server's answer: %w", err)
	}
	return nil
}

// connectError explains why a request did not get through: nothing
// answered, or something answered that is not the CA the client trusts.
// The second can be a wrong --ca-url or --root, or someone in between, so
// it must not read like a network problem.
func connectError(baseURL string, err error) error {
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return fmt.Errorf("the CA server's certificate is not valid for the address %s: use an address from the server's server.names: %w", baseURL, err)
	}
	var unknown x509.UnknownAuthorityError
	var verify *tls.CertificateVerificationError
	if errors.As(err, &unknown) || errors.As(err, &verify) {
		return fmt.Errorf("the server at %s is not the CA you trust: its certificate does not come from your root certificate. "+
			"Check --ca-url and --root (or what \"bxp trust\" saved); otherwise, someone may be in between: %w", baseURL, err)
	}
	return fmt.Errorf("cannot reach the CA server at %s: %w", baseURL, err)
}
