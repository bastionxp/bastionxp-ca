// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// The server's own TLS certificate comes from the CA and works for clients
// that trust only the root, by IP address and by DNS name.
func TestNewTLSConfigServesACertificateFromTheCA(t *testing.T) {
	env := newTestEnv(t)
	tlsConfig, err := NewTLSConfig(env.ca, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}

	// Not httptest.NewTLSServer: that one adds its own test certificate.
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: env.handler}
	go srv.Serve(listener)
	defer srv.Close()

	// A client that trusts nothing but the CA's root certificate.
	roots := x509.NewCertPool()
	roots.AddCert(env.ca.RootCert())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}

	// Reach the server by IP address and by DNS name.
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	urls := []string{"https://127.0.0.1:" + port, "https://localhost:" + port}
	for _, url := range urls {
		resp, err := client.Get(url + "/health")
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status = %d (body: %s)", url, resp.StatusCode, body)
		}
	}
}

// The server's TLS setup needs at least one name.
func TestNewTLSConfigRejectsNoNames(t *testing.T) {
	env := newTestEnv(t)
	if _, err := NewTLSConfig(env.ca, nil); err == nil {
		t.Fatal("expected an error without names, got nil")
	}
}

// The server's own certificate is reused while fresh and replaced once two
// thirds of its life have passed, before it expires.
func TestSelfCertIsRenewedBeforeItExpires(t *testing.T) {
	env := newTestEnv(t)
	self := &selfCert{ca: env.ca, names: []string{"localhost"}}
	now := time.Now()

	first, err := self.get(now)
	if err != nil {
		t.Fatal(err)
	}

	// Early in its life the same certificate is handed out again.
	again, err := self.get(now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Error("a fresh certificate was replaced")
	}

	// Past two thirds of its life a new one is issued, well before the
	// old one stops working.
	lifetime := first.Leaf.NotAfter.Sub(first.Leaf.NotBefore)
	later := first.Leaf.NotBefore.Add(lifetime*2/3 + time.Hour)
	if !later.Before(first.Leaf.NotAfter) {
		t.Fatal("test bug: the renewal time must be before the expiry")
	}
	renewed, err := self.get(later)
	if err != nil {
		t.Fatal(err)
	}
	if renewed == first {
		t.Error("the certificate was not renewed")
	}
}
