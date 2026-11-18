// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
)

func newTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		DataDir: t.TempDir(),
		CA:      config.CA{Name: "Test", Organization: "Test Org", KeyType: config.KeyTypeECDSA},
		Server:  config.Server{Address: "127.0.0.1:0", Names: []string{"localhost", "127.0.0.1"}},
	}
}

// TestInitTokenServe walks through what an administrator does: create the
// CA, start the server, create a token, and get a certificate with it over
// HTTPS.
func TestInitTokenServe(t *testing.T) {
	cfg := newTestConfig(t)
	if err := runInit(io.Discard, cfg, testInit); err != nil {
		t.Fatal(err)
	}

	// Start the server on a free port.
	listener, err := net.Listen("tcp", cfg.Server.Address)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- runServe(ctx, cfg, listener, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), serveHooks{})
	}()

	// bxp token --profile tls-server --name web.example.com
	var out bytes.Buffer
	if err := runToken(&out, cfg, tokenOptions{template: "tls-server", names: []string{"web.example.com"}}); err != nil {
		t.Fatal(err)
	}
	tok := strings.TrimSpace(out.String())

	// The client trusts only root.crt, like a real client would.
	authority, err := ca.Load(cfg.DataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority.RootCert())
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}},
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{DNSNames: []string{"web.example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	body, _ := json.Marshal(map[string]string{"csr": string(csrPEM)})

	url := "https://" + listener.Addr().String() + "/v1/x509/sign"
	post := func() *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := post()
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body: %s)", resp.StatusCode, respBody)
	}
	var signed struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(respBody, &signed); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(signed.Certificate))
	if block == nil {
		t.Fatalf("no certificate in the response: %s", respBody)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "web.example.com" {
		t.Errorf("DNS names = %v, want [web.example.com]", cert.DNSNames)
	}

	// The token is spent.
	resp = post()
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("second use of the token: status = %d, want 401", resp.StatusCode)
	}

	// Stopping must be clean.
	stop()
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("server stopped with an error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server did not stop")
	}
}

// bxp serve refuses to start in a data directory without a CA.
func TestServeNeedsAnInitializedCA(t *testing.T) {
	cfg := newTestConfig(t)
	listener, err := net.Listen("tcp", cfg.Server.Address)
	if err != nil {
		t.Fatal(err)
	}
	err = runServe(context.Background(), cfg, listener, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), serveHooks{})
	if err == nil {
		t.Fatal("expected an error without a CA, got nil")
	}
}

// bxp token refuses an unknown profile, missing names, a lifetime above the
// maximum and a subject with a space, and prints no token when it refuses.
func TestTokenRejectsBadInput(t *testing.T) {
	cfg := newTestConfig(t)
	if err := runInit(io.Discard, cfg, testInit); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		subject  string
		template string
		names    []string
		validFor time.Duration
		wantErr  string
	}{
		{"unknown profile", "", "tls-everything", []string{"a.example.com"}, 0, "unknown profile"},
		{"no names for SSH", "", "ssh-user", nil, 0, "--name"},
		{"no names", "", "tls-server", nil, 0, "--name"},
		{"valid for too long", "", "tls-server", []string{"a.example.com"}, 48 * time.Hour, "above the maximum"},
		{"subject with a space", "alice smith", "ssh-user", []string{"deploy"}, 0, "subject"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			err := runToken(&out, cfg, tokenOptions{subject: tt.subject, template: tt.template, names: tt.names, validFor: tt.validFor})
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
			if out.Len() != 0 {
				t.Errorf("a token was printed despite the error: %s", out.String())
			}
		})
	}
}

// bxp token refuses to make a token without a CA.
func TestTokenNeedsAnInitializedCA(t *testing.T) {
	cfg := newTestConfig(t)
	var out bytes.Buffer
	if err := runToken(&out, cfg, tokenOptions{template: "tls-server", names: []string{"a.example.com"}}); err == nil {
		t.Fatal("expected an error without a CA, got nil")
	}
}

// bxp token asks the server only on an admin's machine (--ca-url given, or
// BXP_CA_URL without a configuration file); on the CA machine it makes the
// token itself, even with BXP_CA_URL set.
func TestTokenIsRemote(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "bastionxp-ca.yaml")
	if err := os.WriteFile(present, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.yaml")

	tests := []struct {
		name        string
		urlGiven    bool
		configGiven bool
		configPath  string
		url         string
		want        bool
	}{
		{"CA machine", false, false, present, "", false},
		// BXP_CA_URL set for other commands must not send the CA
		// machine's own tokens over the network.
		{"CA machine with BXP_CA_URL", false, false, present, "https://ca", false},
		{"admin's machine with BXP_CA_URL", false, false, missing, "https://ca", true},
		{"--ca-url wins over a config file", true, false, present, "https://ca", true},
		{"--config means the CA machine", false, true, missing, "https://ca", false},
		{"nothing at all: local, to say what is missing", false, false, missing, "", false},
	}
	for _, tt := range tests {
		if got := tokenIsRemote(tt.urlGiven, tt.configGiven, tt.configPath, tt.url); got != tt.want {
			t.Errorf("%s: remote = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// The command as a person types it: on the CA machine it prints a token;
// with --ca-url it goes to the server and needs no configuration file.
func TestTokenCommand(t *testing.T) {
	// Never the saved trust of whoever runs the tests.
	t.Setenv(envClientDir, t.TempDir())
	t.Setenv(envURL, "")
	cfg := newTestConfig(t)
	if err := runInit(io.Discard, cfg, testInit); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(t.TempDir(), "bastionxp-ca.yaml")
	content := "data_dir: " + cfg.DataDir + "\nca:\n  organization: Test Org\n"
	if err := os.WriteFile(configFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) (string, error) {
		cmd := newRootCommand()
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return out.String(), err
	}

	out, err := run("token", "--config", configFile, "--name", "web.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if tok := strings.TrimSpace(out); tok == "" || strings.ContainsAny(tok, " \n") {
		t.Errorf("output is not one token: %q", out)
	}

	// With --ca-url it asks the server (none is listening here) and does
	// not look for a configuration file.
	_, err = run("token", "--ca-url", "https://127.0.0.1:1", "--config", filepath.Join(t.TempDir(), "none.yaml"), "--name", "web.example.com")
	if err == nil || !strings.Contains(err.Error(), "cannot reach") {
		t.Errorf("with --ca-url: error = %v, want one about reaching the server", err)
	}

	// Neither a configuration file nor an address: say what to do.
	_, err = run("token", "--config", filepath.Join(t.TempDir(), "none.yaml"), "--name", "web.example.com")
	if err == nil || !strings.Contains(err.Error(), "--ca-url") {
		t.Errorf("without either: error = %v, want a hint about --ca-url", err)
	}
}

// The old command names are gone.
func TestNoGetCommand(t *testing.T) {
	cmd := newRootCommand()
	for _, sub := range cmd.Commands() {
		if sub.Name() == "get" || sub.Name() == "request" {
			t.Errorf("the command %q still exists", sub.Name())
		}
	}
}
