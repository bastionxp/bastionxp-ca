// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/config"
)

func accessTestConfig(t *testing.T) *config.Config {
	cfg := newTestConfig(t)
	cfg.OIDC.Issuer = "https://login.example.com"
	cfg.Access = []config.AccessRule{
		{Groups: []string{"linux-users"}, SSHPrincipals: []string{"{short_username}"}},
		{Groups: []string{"dba"}, SSHPrincipals: []string{"postgres"}},
		{Users: []string{"root@example.com"}, Admin: true},
	}
	return cfg
}

// bxp access check shows which rules match a user and what they get, as text
// and JSON: SSH principals and TLS certificates for a user in groups, admin
// for an admin, and a refusal when no rule matches.
func TestAccessCheck(t *testing.T) {
	cfg := accessTestConfig(t)
	check := func(opts accessCheckOptions) string {
		t.Helper()
		var out bytes.Buffer
		if err := runAccessCheck(&out, cfg, opts); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}

	got := check(accessCheckOptions{user: "alice@example.com", groups: []string{"Linux-Users", "dba"}})
	for _, want := range []string{
		"#1  by group Linux-Users: ssh_principals: {short_username}",
		"#2  by group dba: ssh_principals: postgres",
		"SSH certificate:  ssh-user, for themselves, as alice, postgres",
		"TLS certificate:  tls-client, for alice@example.com",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Admin:") {
		t.Errorf("alice is no admin:\n%s", got)
	}

	got = check(accessCheckOptions{user: "ROOT@example.com"})
	if !strings.Contains(got, "#3  by user: admin") || !strings.Contains(got, "Admin:            one-time tokens") {
		t.Errorf("admin:\n%s", got)
	}

	got = check(accessCheckOptions{user: "carol@example.com", groups: []string{"sales"}})
	if !strings.Contains(got, "none: no rule names") || !strings.Contains(got, "Nothing: a login is refused.") {
		t.Errorf("no rule:\n%s", got)
	}

	var result accessCheckJSON
	if err := json.Unmarshal([]byte(check(accessCheckOptions{user: "alice@example.com", groups: []string{"dba"}, format: "json"})), &result); err != nil {
		t.Fatal(err)
	}
	if !result.MayLogIn || result.Admin || result.SSH == nil || !slices.Equal(result.SSH.Principals, []string{"postgres"}) ||
		len(result.Rules) != 1 || result.Rules[0].Rule != 2 || result.TLS == nil {
		t.Errorf("JSON: %+v", result)
	}
}

// bxp access check uses the one login that is set up, asks for --login when
// both are, refuses an unknown login, and needs --user.
func TestAccessCheckLogin(t *testing.T) {
	cfg := accessTestConfig(t)
	if login, err := chooseLogin(cfg, ""); err != nil || login != "oidc" {
		t.Errorf("OIDC only: %q, %v", login, err)
	}
	cfg.LDAP.URL = "ldaps://dc.example.com"
	if _, err := chooseLogin(cfg, ""); err == nil || !strings.Contains(err.Error(), "--login") {
		t.Errorf("both set up: error = %v, want one asking for --login", err)
	}
	if login, err := chooseLogin(cfg, "ldap"); err != nil || login != "ldap" {
		t.Errorf("--login ldap: %q, %v", login, err)
	}
	if _, err := chooseLogin(cfg, "saml"); err == nil {
		t.Error("--login saml accepted")
	}
	if err := runAccessCheck(&bytes.Buffer{}, cfg, accessCheckOptions{login: "ldap"}); err == nil || !strings.Contains(err.Error(), "--user") {
		t.Errorf("no user: error = %v", err)
	}
}
