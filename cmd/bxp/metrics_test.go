// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/config"
)

func scrape(t *testing.T, address, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+address+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// The metrics, behind their token and on their own address, count issued
// certificates by kind and verifier, logins, refusals, certificates by
// state, the CA certificates' expiry, the build, and requests by route; they
// contain no serial numbers or names.
func TestMetrics(t *testing.T) {
	address := freeAddress(t)
	tokenFile := writeSecret(t, "prometheus-token\n")
	testCA := startTestCA(t, func(cfg *config.Config) {
		cfg.Metrics = config.Metrics{Address: address, TokenFile: tokenFile}
	})

	// A certificate from a token, then revoked; a login in the browser; a
	// refused token.
	leaf, _ := testCA.issueTLS(t, "web.example.com")
	if err := runRevoke(context.Background(), io.Discard, testCA.cfg, leaf.SerialNumber.Text(16), "key-compromise", false); err != nil {
		t.Fatal(err)
	}
	conn := testCA.oidcBrowser(t, testCA.idp, "alice@corp.example.com", "linux-users")
	if err := runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: writeSSHKey(t, t.TempDir()), template: "ssh-user"}); err != nil {
		t.Fatal(err)
	}
	bad := connection{url: testCA.url, root: testCA.root, token: "not-a-token", prompt: io.Discard}
	_ = runTLS(context.Background(), io.Discard, bad, tlsOptions{names: []string{"x.example.com"}, outDir: t.TempDir()})

	if status, _ := scrape(t, address, ""); status != http.StatusUnauthorized {
		t.Errorf("without the token: status %d, want 401", status)
	}
	status, out := scrape(t, address, "prometheus-token")
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	for _, want := range []string{
		`bastionxp_ca_certificates_issued_total{kind="tls-server",verifier="token"} 1`,
		`bastionxp_ca_certificates_issued_total{kind="ssh-user",verifier="login"} 1`,
		`bastionxp_ca_logins_total{method="oidc",result="success"} 1`,
		`bastionxp_ca_requests_refused_total{reason="invalid_token"} 1`,
		`bastionxp_ca_certificates{kind="tls-server",state="revoked"} 1`,
		`bastionxp_ca_certificates{kind="bastionxp-ca-server",state="valid"} 1`,
		`bastionxp_ca_ca_certificate_expiry_timestamp_seconds{certificate="intermediate"}`,
		`bastionxp_ca_build_info{version="dev"} 1`,
		`route="POST /v1/x509/sign",code="201"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	// Counts only: no serial numbers or names.
	for _, secret := range []string{leaf.SerialNumber.Text(16), "web.example.com", "alice"} {
		if strings.Contains(out, secret) {
			t.Errorf("the metrics contain %q", secret)
		}
	}
	// Not on the CA's own address.
	resp, err := (&http.Client{Transport: &http.Transport{}}).Get(strings.Replace(testCA.url, "https", "http", 1) + "/metrics")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Error("metrics are served on the CA's address")
		}
	}
}

// Without metrics.address there is no metrics endpoint.
func TestMetricsOffByDefault(t *testing.T) {
	testCA := startTestCA(t)
	if testCA.cfg.Metrics.Address != "" {
		t.Fatal("metrics on in the test configuration")
	}
}
