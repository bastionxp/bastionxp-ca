// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// addACMEData puts two accounts and three orders into the CA's database:
// one issued, one whose proof failed, and one that ran out of time.
func addACMEData(t *testing.T, testCA *testCA) {
	t.Helper()
	db, err := store.Open(filepath.Join(testCA.cfg.DataDir, store.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()

	for _, a := range []store.ACMEAccount{
		{ID: "acct-certbot", Thumbprint: "t1", JWK: "{}", Contact: []string{"mailto:ops@example.com"}},
		{ID: "acct-lego", Thumbprint: "t2", JWK: "{}"},
	} {
		if _, _, err := db.CreateACMEAccount(ctx, a); err != nil {
			t.Fatal(err)
		}
	}

	order := func(id, account string, expires time.Time, names ...string) {
		t.Helper()
		var authzs []store.ACMEAuthz
		for _, n := range names {
			authzs = append(authzs, store.ACMEAuthz{ID: id + "-" + n, Name: n, Token: "tok-" + n, Expires: expires})
		}
		if err := db.CreateACMEOrder(ctx, store.ACMEOrder{ID: id, AccountID: account, Names: names, Expires: expires}, authzs); err != nil {
			t.Fatal(err)
		}
	}
	later := time.Now().Add(20 * time.Hour)
	// Created first, so the next new orders do not tidy it away.
	order("o-old", "acct-lego", time.Now().Add(time.Second), "old.example.com")
	order("o-issued", "acct-certbot", later, "web.example.com", "www.example.com")
	order("o-failed", "acct-certbot", later.Add(time.Hour), "api.example.com")

	for _, n := range []string{"web.example.com", "www.example.com"} {
		if _, err := db.FinishACMEAuthz(ctx, "o-issued-"+n, store.ACMEValid, "http-01", ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.SetACMEOrderCertificate(ctx, "o-issued", "1a2b3c", "PEM"); err != nil {
		t.Fatal(err)
	}
	// Saved as the server saves it: the ACME problem sent to the client.
	if _, err := db.FinishACMEAuthz(ctx, "o-failed-api.example.com", store.ACMEInvalid, "http-01",
		`{"type":"urn:ietf:params:acme:error:connection","detail":"connection refused on port 80"}`); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // o-old runs out of time
}

// bxp list acme-accounts shows each account with its contact and creation
// date, as text and as JSON.
func TestListACMEAccounts(t *testing.T) {
	testCA := startTestCA(t)
	addACMEData(t, testCA)
	ctx := context.Background()

	var out bytes.Buffer
	if err := runListACMEAccounts(ctx, &out, testCA.cfg, "text"); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"ACCOUNT", "acct-certbot", "mailto:ops@example.com", "acct-lego", time.Now().Format("2006-01-02")} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}

	out.Reset()
	if err := runListACMEAccounts(ctx, &out, testCA.cfg, "json"); err != nil {
		t.Fatal(err)
	}
	var accounts []acmeAccountJSON
	if err := json.Unmarshal(out.Bytes(), &accounts); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out.String())
	}
	if len(accounts) != 2 {
		t.Fatalf("%d accounts, want 2:\n%s", len(accounts), out.String())
	}
	for _, a := range accounts {
		if _, err := time.Parse(time.RFC3339, a.Created); err != nil || a.Status != "valid" || a.Contact == nil {
			t.Errorf("account = %+v", a)
		}
	}
}

// bxp list acme-orders shows orders with their names, status and challenge,
// without trailing spaces; --failed and --name filter them; JSON lists them
// newest first with their authorizations.
func TestListACMEOrders(t *testing.T) {
	testCA := startTestCA(t)
	addACMEData(t, testCA)
	ctx := context.Background()

	list := func(failed bool, name, format string) string {
		t.Helper()
		var out bytes.Buffer
		if err := runListACMEOrders(ctx, &out, testCA.cfg, failed, name, format); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}

	all := list(false, "", "text")
	for _, want := range []string{
		"Order o-issued  valid  account acct-certbot",
		"certificate 1a2b3c",
		"web.example.com  valid  http-01\n", // no trailing spaces
		"Order o-failed  invalid",
		"api.example.com  invalid  http-01  connection: connection refused on port 80\n",
		"Order o-old  expired",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("output lacks %q:\n%s", want, all)
		}
	}

	failed := list(true, "", "text")
	if !strings.Contains(failed, "o-failed") || strings.Contains(failed, "o-issued") || strings.Contains(failed, "o-old") {
		t.Errorf("--failed shows:\n%s", failed)
	}
	byName := list(false, "WWW.example.com", "text")
	if !strings.Contains(byName, "o-issued") || strings.Contains(byName, "o-failed") {
		t.Errorf("--name www.example.com shows:\n%s", byName)
	}
	if none := list(true, "web.example.com", "text"); strings.TrimSpace(none) != "No ACME orders." {
		t.Errorf("no match shows:\n%s", none)
	}

	var orders []acmeOrderJSON
	if err := json.Unmarshal([]byte(list(false, "", "json")), &orders); err != nil {
		t.Fatal(err)
	}
	if len(orders) != 3 || orders[0].ID != "o-failed" {
		t.Fatalf("orders = %+v, want 3, newest (o-failed) first", orders)
	}
	if a := orders[0].Authorizations; len(a) != 1 || a[0].Error != "connection refused on port 80" ||
		a[0].ErrorType != "connection" || a[0].Challenge != "http-01" {
		t.Errorf("o-failed authorizations = %+v", a)
	}
	if orders[1].State != "valid" || orders[1].Serial != "1a2b3c" || len(orders[1].Authorizations) != 2 {
		t.Errorf("o-issued = %+v", orders[1])
	}
}

// The list commands refuse an unknown --format.
func TestListFormatChecked(t *testing.T) {
	for _, args := range [][]string{
		{"list", "certificates", "--format", "yaml"},
		{"list", "acme-accounts", "--format", "xml"},
		{"list", "acme-orders", "--format", "csv"},
	} {
		cmd := newRootCommand()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "use text or json") {
			t.Errorf("%v: error = %v", args, err)
		}
	}
}

// bxp list certificates --format json gives each certificate's fields, with
// the end time in a standard form.
func TestListCertificatesJSON(t *testing.T) {
	testCA := startTestCA(t)
	cert, _ := testCA.issueTLS(t, "web.example.com")
	var out bytes.Buffer
	if err := runListCertificates(context.Background(), &out, testCA.cfg, false, "json"); err != nil {
		t.Fatal(err)
	}
	var certs []certificateJSON
	if err := json.Unmarshal(out.Bytes(), &certs); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range certs {
		if c.Serial == store.X509Serial(cert.SerialNumber) {
			found = true
			if c.Status != "valid" || c.Profile != "tls-server" || len(c.Names) != 1 {
				t.Errorf("certificate = %+v", c)
			}
			if _, err := time.Parse(time.RFC3339, c.NotAfter); err != nil {
				t.Errorf("not_after %q: %v", c.NotAfter, err)
			}
		}
	}
	if !found {
		t.Errorf("the certificate is not in the JSON:\n%s", out.String())
	}
}
