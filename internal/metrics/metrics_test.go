// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Metrics are written in the Prometheus text format, counters declared even
// before they have values.
func TestFormat(t *testing.T) {
	m := NewCA()
	m.Issued("ssh-user", "login")
	m.Issued("ssh-user", "login")
	m.Issued("tls-server", "acme")
	m.Refused(RefusedUsed)
	m.Request("POST /v1/ssh/sign", 201, 250*time.Millisecond)
	m.Request("POST /v1/ssh/sign", 201, 750*time.Millisecond)
	m.Registry.Gauge("bastionxp_ca_test_gauge", "A gauge.", []string{"name"},
		func(_ context.Context, emit func([]string, float64)) { emit([]string{`a"b\c`}, 1.5) })

	var b strings.Builder
	if err := m.Registry.Write(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# TYPE bastionxp_ca_certificates_issued_total counter\n",
		`bastionxp_ca_certificates_issued_total{kind="ssh-user",verifier="login"} 2` + "\n",
		`bastionxp_ca_certificates_issued_total{kind="tls-server",verifier="acme"} 1` + "\n",
		`bastionxp_ca_requests_refused_total{reason="token_used"} 1` + "\n",
		"# TYPE bastionxp_ca_http_request_duration_seconds summary\n",
		`bastionxp_ca_http_request_duration_seconds_sum{route="POST /v1/ssh/sign",code="201"} 1` + "\n",
		`bastionxp_ca_http_request_duration_seconds_count{route="POST /v1/ssh/sign",code="201"} 2` + "\n",
		`bastionxp_ca_test_gauge{name="a\"b\\c"} 1.5` + "\n",
		"# TYPE bastionxp_ca_logins_total counter\n", // declared even with no values yet
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// Code without metrics calls the same methods on nil.
func TestNilCountsNothing(t *testing.T) {
	var m *CA
	m.Issued("x", "y")
	m.Refused("x")
	m.Login("x", "y")
	m.Request("x", 200, time.Second)
}

// The metrics endpoint needs the right bearer token: none, a wrong one, or
// Basic gets 401.
func TestHandlerToken(t *testing.T) {
	h := NewCA().Registry.Handler("s3cret")
	for _, tt := range []struct {
		header string
		want   int
	}{
		{"", http.StatusUnauthorized},
		{"Bearer wrong", http.StatusUnauthorized},
		{"Basic s3cret", http.StatusUnauthorized},
		{"Bearer s3cret", http.StatusOK},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		if tt.header != "" {
			req.Header.Set("Authorization", tt.header)
		}
		h.ServeHTTP(rec, req)
		if rec.Code != tt.want {
			t.Errorf("%q: status %d, want %d", tt.header, rec.Code, tt.want)
		}
	}
}
