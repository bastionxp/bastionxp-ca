// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/api"
)

// newTestServer starts an HTTPS server with the given handler and returns
// a client that trusts it. It stands in for a real BastionXP CA server: the
// tests with a real one are in cmd/bxp.
func newTestServer(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	// Write the test server's certificate to a file, to use it as the root.
	rootFile := filepath.Join(t.TempDir(), "root.crt")
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(rootFile, rootPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := New(srv.URL, rootFile)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The client sends a TLS request as POST to the sign endpoint, with the
// token as a bearer token and the request as the body, and returns the
// answer.
func TestSignX509SendsTokenAndRequest(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != api.SignX509Path {
			t.Errorf("request = %s %s, want POST %s", r.Method, r.URL.Path, api.SignX509Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer my-token" {
			t.Errorf("Authorization = %q, want Bearer my-token", got)
		}
		var req api.SignX509Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req.CSR != "my-csr" || req.Validity != "24h" {
			t.Errorf("request body = %+v", req)
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(api.SignX509Response{Certificate: "cert", Chain: "chain"})
	})

	resp, err := c.SignX509(context.Background(), "my-token", api.SignX509Request{CSR: "my-csr", Validity: "24h"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Certificate != "cert" || resp.Chain != "chain" {
		t.Errorf("response = %+v", resp)
	}
}

// The client sends an SSH request as POST to the sign endpoint, with the
// token as a bearer token and the request as the body, and returns the
// answer.
func TestSignSSHSendsTokenAndRequest(t *testing.T) {
	c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != api.SignSSHPath {
			t.Errorf("request = %s %s, want POST %s", r.Method, r.URL.Path, api.SignSSHPath)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer my-token" {
			t.Errorf("Authorization = %q, want Bearer my-token", got)
		}
		var req api.SignSSHRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req.PublicKey != "my-key" || len(req.Principals) != 1 || req.Principals[0] != "alice" {
			t.Errorf("request body = %+v", req)
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(api.SignSSHResponse{Certificate: "ssh-cert"})
	})

	resp, err := c.SignSSH(context.Background(), "my-token", api.SignSSHRequest{PublicKey: "my-key", Principals: []string{"alice"}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Certificate != "ssh-cert" {
		t.Errorf("response = %+v", resp)
	}
}

// The client reports the CA's error message, an error that is not from the
// CA by its status, a success without a certificate, and a success that is
// not JSON.
func TestServerErrorsAreReported(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{
			"error message from the CA",
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(api.Error{Error: "this token was already used"})
			},
			"refused the request: this token was already used",
		},
		{
			"error that is not from the CA",
			func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "<html>bad gateway</html>", http.StatusBadGateway)
			},
			"502",
		},
		{
			"success without a certificate",
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte(`{}`))
			},
			"no certificate",
		},
		{
			"success that is not JSON",
			func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`hello`))
			},
			"cannot understand",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestServer(t, tt.handler)

			_, err := c.SignX509(context.Background(), "tok", api.SignX509Request{CSR: "csr"})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("SignX509 error = %v, want it to contain %q", err, tt.wantErr)
			}
			_, err = c.SignSSH(context.Background(), "tok", api.SignSSHRequest{PublicKey: "key"})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("SignSSH error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// Without the CA's root, the client refuses a server it does not trust,
// before its request and token reach it.
func TestClientDoesNotTrustAnUnknownServer(t *testing.T) {
	called := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	// No root file: the client uses the operating system's roots, and
	// those do not know the test server's certificate.
	c, err := New(srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.SignX509(context.Background(), "tok", api.SignX509Request{CSR: "csr"})
	if err == nil || !strings.Contains(err.Error(), "is not the CA you trust") {
		t.Errorf("error = %v, want one saying the server is not the trusted CA", err)
	}
	if called {
		t.Error("the request, with its token, reached a server the client must not trust")
	}
}

// The client refuses a missing URL, one without a scheme or over plain HTTP,
// a missing root file and one without a certificate.
func TestNewRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	notACert := filepath.Join(dir, "empty.crt")
	if err := os.WriteFile(notACert, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		serverURL string
		rootFile  string
		wantErr   string
	}{
		{"no URL", "", "", "invalid server URL"},
		{"no scheme", "ca.example.com:8443", "", "invalid server URL"},
		{"plain http", "http://ca.example.com:8443", "", "must start with https://"},
		{"root file missing", "https://ca.example.com", filepath.Join(dir, "nope.crt"), "read root certificate"},
		{"root file without certificate", "https://ca.example.com", notACert, "no PEM certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.serverURL, tt.rootFile)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// The login address is built from the CA's URL, without a double slash, and
// the parameters.
func TestLoginURL(t *testing.T) {
	c, err := New("https://ca.example.com:8443/", "")
	if err != nil {
		t.Fatal(err)
	}
	got := c.LoginURL(api.OIDCLoginPath, url.Values{api.LoginProfile: {"ssh-user"}, api.LoginName: {"a", "b"}})
	want := "https://ca.example.com:8443/v1/oidc/login?name=a&name=b&profile=ssh-user"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// The client learns whether the CA has a login set up from a GET to the
// login endpoint, without sending any secret.
func TestLoginIsSetUp(t *testing.T) {
	tests := []struct {
		status int
		want   bool
	}{
		{http.StatusBadRequest, true}, // "parameters are missing"
		{http.StatusNotFound, false},  // "not set up"
	}
	for _, tt := range tests {
		c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != api.OIDCLoginPath {
				t.Errorf("request = %s %s, want GET %s", r.Method, r.URL.Path, api.OIDCLoginPath)
			}
			// The check must not carry any secret.
			if r.Header.Get("Authorization") != "" || r.URL.RawQuery != "" {
				t.Errorf("the check sends more than it should: %s %v", r.URL.RawQuery, r.Header)
			}
			w.WriteHeader(tt.status)
		})
		got, err := c.LoginIsSetUp(context.Background(), api.OIDCLoginPath)
		if err != nil || got != tt.want {
			t.Errorf("status %d: got %v, %v; want %v", tt.status, got, err, tt.want)
		}
	}
}

// The right CA, at an address its certificate is not for: said so, not as
// a network problem.
func TestClientAddressNotInTheCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	root := filepath.Join(t.TempDir(), "root.crt")
	if err := os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	// The test server's certificate is for 127.0.0.1 and example.com,
	// not for "localhost".
	c, err := New(strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), root)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.SignX509(context.Background(), "tok", api.SignX509Request{CSR: "csr"})
	if err == nil || !strings.Contains(err.Error(), "not valid for the address") {
		t.Errorf("error = %v, want one about the address", err)
	}
}
