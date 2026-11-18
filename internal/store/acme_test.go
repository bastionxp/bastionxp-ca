// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func testAccount(id, thumbprint string) ACMEAccount {
	return ACMEAccount{ID: id, Thumbprint: thumbprint, JWK: `{"kty":"EC"}`, Contact: []string{"mailto:admin@example.com"}, Status: ACMEAccountValid}
}

// An ACME account is created once, with its creation time, and found by ID
// or key thumbprint; the same key again returns the first account; unknown
// accounts and keys are not found.
func TestACMEAccount(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	created, isNew, err := s.CreateACMEAccount(ctx, testAccount("acct-1", "thumb-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !isNew || created.ID != "acct-1" {
		t.Errorf("created = %+v, new = %v", created, isNew)
	}

	byID, err := s.ACMEAccount(ctx, "acct-1")
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(byID.Created) > time.Minute || time.Until(byID.Created) > time.Second {
		t.Errorf("created at %v, want about now", byID.Created)
	}
	byID.Created = time.Time{}
	if !reflect.DeepEqual(*byID, testAccount("acct-1", "thumb-1")) {
		t.Errorf("read back %+v", *byID)
	}
	byKey, err := s.ACMEAccountByThumbprint(ctx, "thumb-1")
	if err != nil || byKey.ID != "acct-1" {
		t.Errorf("by thumbprint: %+v, %v", byKey, err)
	}

	// The same key again: the first account is returned, not a second one.
	again, isNew, err := s.CreateACMEAccount(ctx, testAccount("acct-2", "thumb-1"))
	if err != nil {
		t.Fatal(err)
	}
	if isNew || again.ID != "acct-1" {
		t.Errorf("second registration of a key: account %q, new = %v; want acct-1 and false", again.ID, isNew)
	}

	if _, err := s.ACMEAccount(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown account: error = %v, want ErrNotFound", err)
	}
	if _, err := s.ACMEAccountByThumbprint(ctx, "nothing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown key: error = %v, want ErrNotFound", err)
	}
}

// Many registrations with one key at the same time create one account, and
// all get it.
func TestACMEAccountSameKeyManyRequestsAtOnce(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	const attempts = 10
	ids := make([]string, attempts)
	news := make([]bool, attempts)
	var wg sync.WaitGroup
	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			account, isNew, err := s.CreateACMEAccount(ctx, testAccount("acct-"+string(rune('a'+i)), "same-key"))
			if err != nil {
				t.Error(err)
				return
			}
			ids[i], news[i] = account.ID, isNew
		}()
	}
	wg.Wait()

	created := 0
	for i := range attempts {
		if news[i] {
			created++
		}
		if ids[i] != ids[0] {
			t.Errorf("request %d got account %q, request 0 got %q", i, ids[i], ids[0])
		}
	}
	if created != 1 {
		t.Errorf("%d accounts were created for one key, want 1", created)
	}
}

func testOrder(id string, expires time.Time) (ACMEOrder, []ACMEAuthz) {
	order := ACMEOrder{ID: id, AccountID: "acct-1", Names: []string{"a.example.com", "b.example.com"}, Expires: expires}
	authzs := []ACMEAuthz{
		{ID: id + "-authz-a", Name: "a.example.com", Token: "token-a", Expires: expires},
		{ID: id + "-authz-b", Name: "b.example.com", Token: "token-b", Expires: expires},
	}
	return order, authzs
}

// An ACME order and its authorizations are saved and read back, pending; its
// certificate is found by serial number once issued, with its account; an
// empty serial number, unknown orders and unknown authorizations are not
// found.
func TestACMEOrderAndAuthzs(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	expires := time.Now().Add(time.Hour).Truncate(time.Second)

	order, authzs := testOrder("order-1", expires)
	if err := s.CreateACMEOrder(ctx, order, authzs); err != nil {
		t.Fatal(err)
	}

	got, err := s.ACMEOrder(ctx, "order-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.AccountID != "acct-1" || !reflect.DeepEqual(got.Names, order.Names) || !got.Expires.Equal(expires) || got.Certificate != "" {
		t.Errorf("order read back as %+v", *got)
	}

	list, err := s.ACMEAuthzsOfOrder(ctx, "order-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Name != "a.example.com" || list[1].Name != "b.example.com" {
		t.Fatalf("authorizations = %+v", list)
	}
	for _, authz := range list {
		if authz.Status != ACMEPending || authz.OrderID != "order-1" || authz.AccountID != "acct-1" {
			t.Errorf("authorization = %+v, want pending, of order-1 and acct-1", authz)
		}
	}

	one, err := s.ACMEAuthz(ctx, "order-1-authz-b")
	if err != nil || one.Token != "token-b" {
		t.Errorf("authorization b = %+v, %v", one, err)
	}

	if _, err := s.ACMEAccountOfCertificate(ctx, "1a2b"); !errors.Is(err, ErrNotFound) {
		t.Errorf("before issuing: error = %v, want ErrNotFound", err)
	}
	if err := s.SetACMEOrderCertificate(ctx, "order-1", "1a2b", "PEM"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ACMEOrder(ctx, "order-1")
	if got.Certificate != "PEM" {
		t.Errorf("certificate = %q, want PEM", got.Certificate)
	}
	if owner, err := s.ACMEAccountOfCertificate(ctx, "1a2b"); err != nil || owner != "acct-1" {
		t.Errorf("account of the certificate = %q, %v; want acct-1", owner, err)
	}
	// An order without a certificate does not match the empty serial.
	if _, err := s.ACMEAccountOfCertificate(ctx, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty serial: error = %v, want ErrNotFound", err)
	}

	if _, err := s.ACMEOrder(ctx, "nothing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown order: error = %v, want ErrNotFound", err)
	}
	if _, err := s.ACMEAuthz(ctx, "nothing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown authorization: error = %v, want ErrNotFound", err)
	}
}

// An authorization is decided once: a failed proof stays failed with its
// first error; it cannot go back to pending or to an unknown status.
func TestFinishACMEAuthzDecidesOnce(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	order, authzs := testOrder("order-1", time.Now().Add(time.Hour))
	if err := s.CreateACMEOrder(ctx, order, authzs); err != nil {
		t.Fatal(err)
	}

	changed, err := s.FinishACMEAuthz(ctx, "order-1-authz-a", ACMEInvalid, "http-01", "wrong answer")
	if err != nil || !changed {
		t.Fatalf("first decision: changed = %v, error = %v", changed, err)
	}
	// A failed proof must stay failed: it cannot be turned into a
	// success by trying again.
	changed, err = s.FinishACMEAuthz(ctx, "order-1-authz-a", ACMEValid, "http-01", "")
	if err != nil || changed {
		t.Errorf("second decision: changed = %v, error = %v; want false, nil", changed, err)
	}
	authz, _ := s.ACMEAuthz(ctx, "order-1-authz-a")
	if authz.Status != ACMEInvalid || authz.Error != "wrong answer" {
		t.Errorf("authorization = %+v, want invalid with the first error", authz)
	}

	if _, err := s.FinishACMEAuthz(ctx, "order-1-authz-b", "pending", "http-01", ""); err == nil {
		t.Error("expected an error for setting an authorization back to pending")
	}
	if _, err := s.FinishACMEAuthz(ctx, "order-1-authz-b", "anything", "http-01", ""); err == nil {
		t.Error("expected an error for an unknown status")
	}
}

// Expired orders and authorizations are not found, and are removed when the
// next order is created.
func TestExpiredACMEOrdersAreGone(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	old, oldAuthzs := testOrder("old", time.Now().Add(-time.Hour))
	if err := s.CreateACMEOrder(ctx, old, oldAuthzs); err != nil {
		t.Fatal(err)
	}
	// Not found, although the rows are still there.
	if _, err := s.ACMEOrder(ctx, "old"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired order: error = %v, want ErrNotFound", err)
	}
	if _, err := s.ACMEAuthz(ctx, "old-authz-a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired authorization: error = %v, want ErrNotFound", err)
	}

	// The next order tidies them away.
	fresh, freshAuthzs := testOrder("fresh", time.Now().Add(time.Hour))
	if err := s.CreateACMEOrder(ctx, fresh, freshAuthzs); err != nil {
		t.Fatal(err)
	}
	var orders, authzs int
	s.db.QueryRow(`SELECT COUNT(*) FROM acme_orders`).Scan(&orders)
	s.db.QueryRow(`SELECT COUNT(*) FROM acme_authzs`).Scan(&authzs)
	if orders != 1 || authzs != 2 {
		t.Errorf("%d orders and %d authorizations left, want 1 and 2", orders, authzs)
	}
}

// An order is saved with all its authorizations or not at all.
func TestCreateACMEOrderIsAllOrNothing(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)

	order, authzs := testOrder("order-1", expires)
	authzs[1].ID = authzs[0].ID // the second insert fails: same ID twice
	if err := s.CreateACMEOrder(ctx, order, authzs); err == nil {
		t.Fatal("expected an error, got nil")
	}
	if _, err := s.ACMEOrder(ctx, "order-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("the order was saved although its authorizations were not: %v", err)
	}
	list, _ := s.ACMEAuthzsOfOrder(ctx, "order-1")
	if len(list) != 0 {
		t.Errorf("%d authorizations were saved without their order", len(list))
	}
}

// An account's key can be changed, not to another account's key; the old key
// no longer finds the account.
func TestChangeACMEAccountKey(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	for _, a := range []ACMEAccount{testAccount("a", "thumb-a"), testAccount("b", "thumb-b")} {
		if _, _, err := s.CreateACMEAccount(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ChangeACMEAccountKey(ctx, "a", "thumb-new", `{"kty":"OKP"}`); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangeACMEAccountKey(ctx, "a", "thumb-b", `{}`); err != ErrKeyInUse {
		t.Errorf("another account's key: %v, want ErrKeyInUse", err)
	}
	a, err := s.ACMEAccountByThumbprint(ctx, "thumb-new")
	if err != nil || a.ID != "a" || a.JWK != `{"kty":"OKP"}` {
		t.Errorf("account = %+v, %v", a, err)
	}
	if _, err := s.ACMEAccountByThumbprint(ctx, "thumb-a"); err != ErrNotFound {
		t.Errorf("the old key still finds the account: %v", err)
	}
}

// An account is valid when created and deactivated after deactivation.
func TestDeactivateACMEAccount(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	account, _, err := s.CreateACMEAccount(ctx, ACMEAccount{ID: "acct-1", Thumbprint: "tp", JWK: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	if account.Status != ACMEAccountValid {
		t.Errorf("new account status = %q, want valid", account.Status)
	}
	if err := s.DeactivateACMEAccount(ctx, "acct-1"); err != nil {
		t.Fatal(err)
	}
	got, err := s.ACMEAccountByThumbprint(ctx, "tp")
	if err != nil || got.Status != ACMEAccountDeactivated {
		t.Errorf("after deactivation: %+v, %v", got, err)
	}
}

// The lists behind "bxp list acme-accounts" and "bxp list acme-orders".
func TestACMELists(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	for _, id := range []string{"acct-1", "acct-2"} {
		if _, _, err := s.CreateACMEAccount(ctx, testAccount(id, "thumb-"+id)); err != nil {
			t.Fatal(err)
		}
	}
	accounts, err := s.ACMEAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 2 || accounts[0].ID != "acct-2" || accounts[1].ID != "acct-1" {
		t.Fatalf("accounts = %+v, want acct-2 then acct-1", accounts)
	}
	if accounts[0].Created.IsZero() || len(accounts[0].Contact) != 1 {
		t.Errorf("account = %+v, want a creation time and the contact", accounts[0])
	}

	now := time.Now().Truncate(time.Second)
	older, olderAuthzs := testOrder("order-1", now.Add(time.Hour))
	newer, newerAuthzs := testOrder("order-2", now.Add(2*time.Hour))
	for _, o := range []struct {
		order  ACMEOrder
		authzs []ACMEAuthz
	}{{older, olderAuthzs}, {newer, newerAuthzs}} {
		if err := s.CreateACMEOrder(ctx, o.order, o.authzs); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.FinishACMEAuthz(ctx, "order-1-authz-a", ACMEInvalid, "http-01", "connection refused"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetACMEOrderCertificate(ctx, "order-2", "1a2b", "PEM"); err != nil {
		t.Fatal(err)
	}

	orders, err := s.ACMEOrders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(orders) != 2 || orders[0].ID != "order-2" || orders[1].ID != "order-1" {
		t.Fatalf("orders = %+v, want order-2 then order-1", orders)
	}
	if orders[0].Serial != "1a2b" || len(orders[0].Authzs) != 2 {
		t.Errorf("order-2 = %+v, want serial 1a2b and two authorizations", orders[0])
	}
	failed := orders[1].Authzs[0]
	if failed.Status != ACMEInvalid || failed.Challenge != "http-01" || failed.Error != "connection refused" {
		t.Errorf("failed authorization = %+v", failed)
	}
}

// An order is pending while proofs are missing, ready when all are proved,
// valid when issued, and invalid when a proof failed.
func TestACMEOrderStatus(t *testing.T) {
	authz := func(status string) ACMEAuthz { return ACMEAuthz{Status: status} }
	for _, tc := range []struct {
		name        string
		certificate string
		authzs      []ACMEAuthz
		want        string
	}{
		{"waiting for proofs", "", []ACMEAuthz{authz(ACMEValid), authz(ACMEPending)}, ACMEPending},
		{"all proved", "", []ACMEAuthz{authz(ACMEValid), authz(ACMEValid)}, "ready"},
		{"issued", "PEM", []ACMEAuthz{authz(ACMEValid)}, ACMEValid},
		{"one proof failed", "", []ACMEAuthz{authz(ACMEValid), authz(ACMEInvalid)}, ACMEInvalid},
	} {
		order := ACMEOrder{Certificate: tc.certificate}
		if got := order.Status(tc.authzs); got != tc.want {
			t.Errorf("%s: status = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Expired orders go with the next new order, except failed ones: they
// stay for KeepFailedACMEOrdersFor after they expire.
func TestFailedACMEOrdersAreKept(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Now()

	create := func(id string, expires time.Time, failed bool) {
		t.Helper()
		order, authzs := testOrder(id, expires)
		if err := s.CreateACMEOrder(ctx, order, authzs); err != nil {
			t.Fatal(err)
		}
		if failed {
			if _, err := s.FinishACMEAuthz(ctx, id+"-authz-a", ACMEInvalid, "http-01", "refused"); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Oldest first: each new order tidies up before it is saved.
	create("failed-long-ago", now.Add(-KeepFailedACMEOrdersFor-time.Hour), true)
	create("failed-recently", now.Add(-time.Hour), true)
	create("expired", now.Add(-time.Hour), false)
	create("current", now.Add(time.Hour), false)

	orders, err := s.ACMEOrders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, o := range orders {
		ids = append(ids, o.ID)
		if len(o.Authzs) != 2 {
			t.Errorf("order %s has %d authorizations, want 2", o.ID, len(o.Authzs))
		}
	}
	if strings.Join(ids, ",") != "current,failed-recently" {
		t.Errorf("orders left: %v, want current and failed-recently", ids)
	}
	var authzs int
	s.db.QueryRow(`SELECT COUNT(*) FROM acme_authzs`).Scan(&authzs)
	if authzs != 4 {
		t.Errorf("%d authorizations left, want 4 (two orders)", authzs)
	}
	// A kept failed order is only for the list: the ACME server does not
	// find it.
	if _, err := s.ACMEOrder(ctx, "failed-recently"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired failed order: error = %v, want ErrNotFound", err)
	}
}

// An expired order that got a certificate stays while the certificate is
// valid: it says which account may revoke or replace the certificate.
func TestIssuedACMEOrdersStayWithTheirCertificate(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Now()

	issued := func(id string, serial int64, certValidUntil time.Time) {
		t.Helper()
		order, authzs := testOrder(id, now.Add(-time.Hour)) // the order itself has expired
		if err := s.CreateACMEOrder(ctx, order, authzs); err != nil {
			t.Fatal(err)
		}
		cert := newTestX509(t, serial, certValidUntil)
		if err := s.RecordX509(cert, "tls-server", "acme"); err != nil {
			t.Fatal(err)
		}
		if err := s.SetACMEOrderCertificate(ctx, id, X509Serial(cert.SerialNumber), "PEM"); err != nil {
			t.Fatal(err)
		}
	}
	issued("cert-valid", 1001, now.Add(30*24*time.Hour))
	issued("cert-expired", 1002, now.Add(-time.Minute))

	// The next order tidies up.
	fresh, freshAuthzs := testOrder("fresh", now.Add(time.Hour))
	if err := s.CreateACMEOrder(ctx, fresh, freshAuthzs); err != nil {
		t.Fatal(err)
	}
	if owner, err := s.ACMEAccountOfCertificate(ctx, X509Serial(big.NewInt(1001))); err != nil || owner != "acct-1" {
		t.Errorf("account of a valid certificate: %q, %v; want acct-1", owner, err)
	}
	if _, err := s.ACMEAccountOfCertificate(ctx, X509Serial(big.NewInt(1002))); !errors.Is(err, ErrNotFound) {
		t.Errorf("order of an expired certificate: error = %v, want ErrNotFound (removed)", err)
	}
}

// One certificate is replaced by one order (RFC 9773, section 5), unless
// that order failed or ran out of time.
func TestACMEOrderReplaces(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Now()
	const certID = "aki.serial"

	create := func(id string, expires time.Time) error {
		order, authzs := testOrder(id, expires)
		order.Replaces = certID
		return s.CreateACMEOrder(ctx, order, authzs)
	}
	if err := create("first", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := s.ACMEOrder(ctx, "first")
	if err != nil || got.Replaces != certID {
		t.Fatalf("order read back: %+v, %v; want replaces %q", got, err, certID)
	}
	if err := create("second", now.Add(time.Hour)); !errors.Is(err, ErrAlreadyReplaced) {
		t.Fatalf("second order replacing the same certificate: error = %v, want ErrAlreadyReplaced", err)
	}

	// Once the first one failed, another may try.
	if _, err := s.FinishACMEAuthz(ctx, "first-authz-a", ACMEInvalid, "http-01", "refused"); err != nil {
		t.Fatal(err)
	}
	if err := create("third", now.Add(-time.Minute)); err != nil {
		t.Fatalf("after the first failed: %v", err)
	}
	// "third" ran out of time without a certificate: it does not count.
	if err := create("fourth", now.Add(time.Hour)); err != nil {
		t.Fatalf("after an expired, unfinished order: %v", err)
	}
}
