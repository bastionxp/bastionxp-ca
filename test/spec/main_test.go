// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestSentence(t *testing.T) {
	for name, want := range map[string]string{
		"TestSignX509RejectsBadTokens":       "Sign X509 rejects bad tokens",
		"TestExplainACMERateLimit":           "Explain ACME rate limit",
		"TestIPAddressWithHTTP01":            "IP address with HTTP01",
		"TestACMEWithNoDomainsAllowsNothing": "ACME with no domains allows nothing",
		"TestAdminWithoutPrincipalsMayLogIn": "Admin without principals may log in",
		"TestACMEDeactivateOnAnotherCA":      "ACME deactivate on another CA",
		"TestIPAddressWithTLSALPN01":         "IP address with TLSALPN01",
		"FuzzCheckDomain":                    "Check domain",
	} {
		if got := sentence(name); got != want {
			t.Errorf("sentence(%q) = %q, want %q", name, got, want)
		}
	}
}

// A test is an integration test if it, or a helper it calls (however
// deep), starts a server; not if a helper merely shares part of the name.
func TestIntegrationThroughHelpers(t *testing.T) {
	funcs := []function{
		{"startServer", "l, _ := net.Listen(\"tcp\", addr)"},
		{"newEnv", "srv := startServer(t)"},
		{"parseThing", "return strings.Fields(s)"},
	}
	marked := integrationHelpers(funcs)
	if !marked["startServer"] || !marked["newEnv"] || marked["parseThing"] {
		t.Fatalf("marked = %v", marked)
	}
	for body, want := range map[string]string{
		"env := newEnv(t)":            levelIntegration,
		"x := parseThing(s)":          levelUnit,
		"y := mynewEnv(t)":            levelUnit, // another function, not newEnv
		"s := startSamba(t)":          levelDocker,
		"r := httptest.NewRecorder()": levelIntegration,
	} {
		if got := levelOf(testCase{Pkg: "internal/x", Name: "TestX"}, body, marked); got != want {
			t.Errorf("%q: level %s, want %s", body, got, want)
		}
	}
}

// A doc comment is shown without the function's name it starts with, by
// Go's convention; a comment that does not start with it is kept whole.
func TestDescribeDropsTheLeadingName(t *testing.T) {
	for _, tc := range []struct {
		c    testCase
		want string
	}{
		{testCase{Name: "FuzzOCSP", Doc: "FuzzOCSP sends arbitrary\nrequests."}, "Sends arbitrary requests."},
		{testCase{Name: "TestX", Doc: "A token works once.\n\nMore detail."}, "A token works once."},
		{testCase{Name: "TestX", Doc: "TestXY is another name."}, "TestXY is another name."},
		{testCase{Name: "TestTokenWorksOnce"}, "Token works once"},
	} {
		if got := describe(tc.c); got != tc.want {
			t.Errorf("describe(%+v) = %q, want %q", tc.c, got, tc.want)
		}
	}
}
