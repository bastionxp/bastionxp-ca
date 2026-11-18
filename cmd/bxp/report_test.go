// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The report holds the checks, the configuration and the database's
// counts, and none of the secrets, people's names or comments.
func TestDoctorReport(t *testing.T) {
	testCA := startTestCA(t)
	addACMEData(t, testCA)

	dir := t.TempDir()
	configFile := filepath.Join(dir, "bastionxp-ca.yaml")
	config := `# Run by Jane Doe, jane.doe@corp.example.com
data_dir: ` + testCA.cfg.DataDir + `
ca:
  organization: Test Org # the legal name
server:
  url: https://ca.invalid:8443
oidc:
  issuer: https://login.invalid
  client_id: bastionxp-ca
  client_secret: "s3cr3t-value" # keep this secret
access:
  - users: [alice@corp.example.com, bob@corp.example.com] # the admins
    admin: true
  - groups: [linux-users]
    ssh_principals: ["{short_username}"]
`
	if err := os.WriteFile(configFile, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	reportFile := filepath.Join(dir, "report.txt")

	run := func() error {
		cmd := newRootCommand()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"doctor", "--config", configFile, "--report=" + reportFile})
		return cmd.Execute()
	}
	run() // the identity provider cannot be reached: a check fails, and the report is written anyway

	data, err := os.ReadFile(reportFile)
	if err != nil {
		t.Fatal(err)
	}
	report := string(data)
	for _, secret := range []string{"s3cr3t", "alice@", "bob@", "Jane", "keep this secret", "the admins", "legal name"} {
		if strings.Contains(report, secret) {
			t.Errorf("the report holds %q:\n%s", secret, report)
		}
	}
	for _, want := range []string{
		"Review this file before you share it",
		"== Checks (bxp doctor)",
		"identity provider cannot be reached",
		`client_secret: "<removed>"`,
		"users: [<user 1>, <user 2>]",
		"groups: [linux-users]",
		"== Database",
		"Schema version:",
		"== Certificates (counts only)",
		"== ACME",
		"Accounts:  2 (valid 2)",
		"api.example.com  http-01  connection: connection refused on port 80",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("the report lacks %q:\n%s", want, report)
		}
	}
	if info, err := os.Stat(reportFile); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("report file mode %v, want 0600", info.Mode())
	}

	// Never over an existing file.
	if err := run(); err == nil || !strings.Contains(err.Error(), "write the report") {
		t.Errorf("second report to the same file: error = %v", err)
	}
}

// A configuration that does not load still gives a report: the error and
// the file.
func TestDoctorReportWithBrokenConfig(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "bastionxp-ca.yaml")
	config := "data_dir: " + dir + "\noidc:\n  issuer: https://login.invalid\n  client_secret: s3cr3t\n"
	if err := os.WriteFile(configFile, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	reportFile := filepath.Join(dir, "report.txt")
	cmd := newRootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"doctor", "--config", configFile, "--report=" + reportFile})
	if err := cmd.Execute(); err == nil {
		t.Error("doctor succeeded on a broken configuration")
	}
	data, err := os.ReadFile(reportFile)
	if err != nil {
		t.Fatal(err)
	}
	report := string(data)
	if !strings.Contains(report, "the configuration does not load") || !strings.Contains(report, "client_secret: <removed>") ||
		strings.Contains(report, "s3cr3t") {
		t.Errorf("report:\n%s", report)
	}
}
