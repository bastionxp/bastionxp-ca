// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// This file stores what the ACME server (internal/acme) has to remember:
// accounts, orders and authorizations.
//
//   - An account is an ACME client, known by its public key.
//   - An order is a request for one certificate, for a list of names.
//   - An authorization belongs to an order and stands for one of its
//     names. It becomes "valid" when the client has proved that it
//     controls the name.

// acmeSchema creates the ACME tables. Like schema, it runs on each start.
const acmeSchema = `
CREATE TABLE IF NOT EXISTS acme_accounts (
	id         TEXT    PRIMARY KEY,
	thumbprint TEXT    NOT NULL UNIQUE,  -- identifies the account's public key
	jwk        TEXT    NOT NULL,         -- the public key, as JSON
	contact    TEXT    NOT NULL,         -- JSON list
	status     TEXT    NOT NULL DEFAULT 'valid', -- valid or deactivated
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS acme_orders (
	id          TEXT    PRIMARY KEY,
	account_id  TEXT    NOT NULL,
	names       TEXT    NOT NULL,          -- JSON list
	certificate TEXT    NOT NULL DEFAULT '', -- PEM chain, empty until issued
	serial      TEXT    NOT NULL DEFAULT '', -- the certificate's serial, hex
	replaces    TEXT    NOT NULL DEFAULT '', -- RFC 9773 ID of the certificate it renews
	expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS acme_orders_serial ON acme_orders (serial);
CREATE INDEX IF NOT EXISTS acme_orders_replaces ON acme_orders (replaces);
CREATE TABLE IF NOT EXISTS acme_authzs (
	id         TEXT    PRIMARY KEY,
	order_id   TEXT    NOT NULL,
	account_id TEXT    NOT NULL,
	name       TEXT    NOT NULL,
	token      TEXT    NOT NULL,
	status     TEXT    NOT NULL,           -- pending, valid or invalid
	error      TEXT    NOT NULL DEFAULT '',
	challenge  TEXT    NOT NULL DEFAULT '', -- the challenge type that decided it
	expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS acme_authzs_order ON acme_authzs (order_id);
`

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("not found")

// KeepFailedACMEOrdersFor is how long an order where a proof failed is
// kept after it expires, so that "bxp list acme-orders --failed" can
// show why a client did not get its certificate. An order that got a
// certificate stays while the certificate is valid: it says which
// account may revoke or replace it. Other orders go when they expire.
const KeepFailedACMEOrdersFor = 7 * 24 * time.Hour

// ErrAlreadyReplaced is returned by CreateACMEOrder when another order
// already replaces the same certificate (RFC 9773, section 5).
var ErrAlreadyReplaced = errors.New("the certificate was already replaced by another order")

// Statuses of an ACME authorization.
const (
	ACMEPending = "pending" // waiting for the client to prove control
	ACMEValid   = "valid"   // control was proved
	ACMEInvalid = "invalid" // the proof failed; the order is lost
)

// Statuses of an ACME account.
const (
	ACMEAccountValid       = "valid"
	ACMEAccountDeactivated = "deactivated" // closed by the client, for good
)

// ACMEAccount is one ACME client.
type ACMEAccount struct {
	ID string
	// Thumbprint identifies the account's public key.
	Thumbprint string
	// JWK is the account's public key, as JSON.
	JWK string
	// Contact is what the client gave as contact addresses.
	Contact []string
	// Status is ACMEAccountValid or ACMEAccountDeactivated.
	Status string
	// Created is when the account was made. Set when it is read.
	Created time.Time
}

// ErrKeyInUse is returned by ChangeACMEAccountKey when another account
// has the new key.
var ErrKeyInUse = errors.New("the key belongs to another account")

// ACMEOrder is a request for one certificate.
type ACMEOrder struct {
	ID        string
	AccountID string
	Names     []string
	// Certificate is the issued certificate chain in PEM format, or
	// empty while there is none.
	Certificate string
	// Serial is the issued certificate's serial number (hex), or empty
	// while there is none. Set when the order is read.
	Serial string
	// Replaces is the ACME renewal information ID (RFC 9773) of the
	// certificate this order renews, as the client sent it; or empty.
	Replaces string
	Expires  time.Time
}

// Status works out the status of an order from its authorizations, as
// RFC 8555 names it: invalid, valid, ready or pending.
func (o *ACMEOrder) Status(authzs []ACMEAuthz) string {
	allValid := true
	for _, authz := range authzs {
		if authz.Status == ACMEInvalid {
			return ACMEInvalid // one failed proof loses the whole order
		}
		if authz.Status != ACMEValid {
			allValid = false
		}
	}
	switch {
	case o.Certificate != "":
		return ACMEValid // the certificate is there
	case allValid:
		return "ready" // waiting for the CSR
	default:
		return ACMEPending // waiting for proofs
	}
}

// ACMEAuthz is the authorization for one name of an order.
type ACMEAuthz struct {
	ID        string
	OrderID   string
	AccountID string
	Name      string
	// Token is the random value the client has to present.
	Token  string
	Status string
	// Error says why the status is invalid.
	Error string
	// Challenge is the type of the challenge that decided the status,
	// e.g. "dns-01"; empty while pending.
	Challenge string
	Expires   time.Time
}

// CreateACMEAccount saves a new account. If an account with the same key
// exists already, that one is returned and created is false.
func (s *Store) CreateACMEAccount(ctx context.Context, account ACMEAccount) (result *ACMEAccount, created bool, err error) {
	contact, err := json.Marshal(account.Contact)
	if err != nil {
		return nil, false, err
	}
	// The thumbprint column is unique, so of two requests with the same
	// key only one inserts. The other finds the first one's account.
	res, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO acme_accounts (id, thumbprint, jwk, contact, created_at) VALUES (?, ?, ?, ?, ?)`,
		account.ID, account.Thumbprint, account.JWK, string(contact), time.Now().Unix())
	if err != nil {
		return nil, false, fmt.Errorf("create ACME account: %w", err)
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return nil, false, fmt.Errorf("create ACME account: %w", err)
	}
	existing, err := s.ACMEAccountByThumbprint(ctx, account.Thumbprint)
	if err != nil {
		return nil, false, err
	}
	return existing, inserted == 1, nil
}

// ACMEAccount returns the account with the given ID, or ErrNotFound.
func (s *Store) ACMEAccount(ctx context.Context, id string) (*ACMEAccount, error) {
	return s.acmeAccount(ctx, `id = ?`, id)
}

// ACMEAccountByThumbprint returns the account with the given key, or ErrNotFound.
func (s *Store) ACMEAccountByThumbprint(ctx context.Context, thumbprint string) (*ACMEAccount, error) {
	return s.acmeAccount(ctx, `thumbprint = ?`, thumbprint)
}

func (s *Store) acmeAccount(ctx context.Context, where, arg string) (*ACMEAccount, error) {
	account, err := scanACMEAccount(s.db.QueryRowContext(ctx,
		`SELECT `+acmeAccountColumns+` FROM acme_accounts WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read ACME account: %w", err)
	}
	return account, nil
}

const acmeAccountColumns = `id, thumbprint, jwk, contact, status, created_at`

func scanACMEAccount(row interface{ Scan(...any) error }) (*ACMEAccount, error) {
	var account ACMEAccount
	var contact string
	var created int64
	err := row.Scan(&account.ID, &account.Thumbprint, &account.JWK, &contact, &account.Status, &created)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(contact), &account.Contact); err != nil {
		return nil, err
	}
	account.Created = time.Unix(created, 0)
	return &account, nil
}

// ACMEAccounts returns all ACME accounts, newest first. For "bxp list
// acme-accounts".
func (s *Store) ACMEAccounts(ctx context.Context) ([]ACMEAccount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+acmeAccountColumns+` FROM acme_accounts ORDER BY created_at DESC, rowid DESC`)
	if err != nil {
		return nil, fmt.Errorf("read ACME accounts: %w", err)
	}
	defer rows.Close()

	var accounts []ACMEAccount
	for rows.Next() {
		account, err := scanACMEAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("read ACME accounts: %w", err)
		}
		accounts = append(accounts, *account)
	}
	return accounts, rows.Err()
}

// ACMEOrderWithAuthzs is an order and its authorizations.
type ACMEOrderWithAuthzs struct {
	ACMEOrder
	Authzs []ACMEAuthz
}

// ACMEOrders returns every order still in the database, newest first,
// each with its authorizations, expired ones included: they stay until
// the next new order removes them, failed ones for
// KeepFailedACMEOrdersFor after they expire. For "bxp list acme-orders".
func (s *Store) ACMEOrders(ctx context.Context) ([]ACMEOrderWithAuthzs, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, account_id, names, certificate, serial, replaces, expires_at FROM acme_orders ORDER BY expires_at DESC, rowid DESC`)
	if err != nil {
		return nil, fmt.Errorf("read ACME orders: %w", err)
	}
	defer rows.Close()

	var orders []ACMEOrderWithAuthzs
	byID := map[string]int{}
	for rows.Next() {
		var o ACMEOrderWithAuthzs
		var names string
		var expires int64
		if err := rows.Scan(&o.ID, &o.AccountID, &names, &o.Certificate, &o.Serial, &o.Replaces, &expires); err != nil {
			return nil, fmt.Errorf("read ACME orders: %w", err)
		}
		if err := json.Unmarshal([]byte(names), &o.Names); err != nil {
			return nil, fmt.Errorf("read ACME orders: %w", err)
		}
		o.Expires = time.Unix(expires, 0)
		byID[o.ID] = len(orders)
		orders = append(orders, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read ACME orders: %w", err)
	}
	rows.Close()

	authzRows, err := s.db.QueryContext(ctx, `SELECT `+acmeAuthzColumns+` FROM acme_authzs ORDER BY rowid`)
	if err != nil {
		return nil, fmt.Errorf("read ACME authorizations: %w", err)
	}
	defer authzRows.Close()
	for authzRows.Next() {
		authz, err := scanACMEAuthz(authzRows)
		if err != nil {
			return nil, fmt.Errorf("read ACME authorizations: %w", err)
		}
		if i, ok := byID[authz.OrderID]; ok {
			orders[i].Authzs = append(orders[i].Authzs, *authz)
		}
	}
	return orders, authzRows.Err()
}

// CreateACMEOrder saves a new order together with its authorizations.
// Either all of it is saved or nothing.
func (s *Store) CreateACMEOrder(ctx context.Context, order ACMEOrder, authzs []ACMEAuthz) error {
	names, err := json.Marshal(order.Names)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("create ACME order: %w", err)
	}
	// After a successful Commit this does nothing.
	defer tx.Rollback()

	// Tidy up orders that have expired, and what belongs to them; see
	// KeepFailedACMEOrdersFor for what stays longer.
	now := time.Now()
	_, err = tx.ExecContext(ctx,
		`DELETE FROM acme_orders WHERE expires_at < ? AND CASE
			WHEN serial != '' THEN NOT EXISTS (
				SELECT 1 FROM certificates WHERE kind = ? AND certificates.serial = acme_orders.serial AND not_after >= ?)
			WHEN EXISTS (
				SELECT 1 FROM acme_authzs WHERE acme_authzs.order_id = acme_orders.id AND acme_authzs.status = ?)
				THEN expires_at < ?
			ELSE 1 END`,
		now.Unix(), KindX509, now.Unix(), ACMEInvalid, now.Add(-KeepFailedACMEOrdersFor).Unix())
	if err != nil {
		return fmt.Errorf("remove expired ACME orders: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM acme_authzs WHERE order_id NOT IN (SELECT id FROM acme_orders)`); err != nil {
		return fmt.Errorf("remove expired ACME authorizations: %w", err)
	}

	// One certificate is replaced by one order at most: another order
	// replacing it counts unless it failed or ran out of time.
	if order.Replaces != "" {
		var taken int
		err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM acme_orders WHERE replaces = ? AND (serial != '' OR expires_at >= ?)
			   AND NOT EXISTS (SELECT 1 FROM acme_authzs WHERE acme_authzs.order_id = acme_orders.id AND acme_authzs.status = ?)`,
			order.Replaces, now.Unix(), ACMEInvalid).Scan(&taken)
		if err != nil {
			return fmt.Errorf("create ACME order: %w", err)
		}
		if taken > 0 {
			return ErrAlreadyReplaced
		}
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO acme_orders (id, account_id, names, replaces, expires_at) VALUES (?, ?, ?, ?, ?)`,
		order.ID, order.AccountID, string(names), order.Replaces, order.Expires.Unix())
	if err != nil {
		return fmt.Errorf("create ACME order: %w", err)
	}
	for _, authz := range authzs {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO acme_authzs (id, order_id, account_id, name, token, status, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			authz.ID, order.ID, order.AccountID, authz.Name, authz.Token, ACMEPending, authz.Expires.Unix())
		if err != nil {
			return fmt.Errorf("create ACME authorization: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("create ACME order: %w", err)
	}
	return nil
}

// ACMEOrder returns the order with the given ID, or ErrNotFound. An order
// that has expired is not found.
func (s *Store) ACMEOrder(ctx context.Context, id string) (*ACMEOrder, error) {
	var order ACMEOrder
	var names string
	var expires int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, account_id, names, certificate, serial, replaces, expires_at FROM acme_orders WHERE id = ? AND expires_at >= ?`,
		id, time.Now().Unix()).
		Scan(&order.ID, &order.AccountID, &names, &order.Certificate, &order.Serial, &order.Replaces, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read ACME order: %w", err)
	}
	if err := json.Unmarshal([]byte(names), &order.Names); err != nil {
		return nil, fmt.Errorf("read ACME order: %w", err)
	}
	order.Expires = time.Unix(expires, 0)
	return &order, nil
}

// SetACMEOrderCertificate saves the certificate issued for an order,
// with its serial number (hex, as X509Serial writes it).
func (s *Store) SetACMEOrderCertificate(ctx context.Context, orderID, serial, certificatePEM string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_orders SET certificate = ?, serial = ? WHERE id = ?`, certificatePEM, serial, orderID)
	if err != nil {
		return fmt.Errorf("save ACME certificate: %w", err)
	}
	return nil
}

const acmeAuthzColumns = `id, order_id, account_id, name, token, status, error, challenge, expires_at`

func scanACMEAuthz(row interface{ Scan(...any) error }) (*ACMEAuthz, error) {
	var authz ACMEAuthz
	var expires int64
	err := row.Scan(&authz.ID, &authz.OrderID, &authz.AccountID, &authz.Name,
		&authz.Token, &authz.Status, &authz.Error, &authz.Challenge, &expires)
	if err != nil {
		return nil, err
	}
	authz.Expires = time.Unix(expires, 0)
	return &authz, nil
}

// ACMEAuthz returns the authorization with the given ID, or ErrNotFound.
// An authorization that has expired is not found.
func (s *Store) ACMEAuthz(ctx context.Context, id string) (*ACMEAuthz, error) {
	authz, err := scanACMEAuthz(s.db.QueryRowContext(ctx,
		`SELECT `+acmeAuthzColumns+` FROM acme_authzs WHERE id = ? AND expires_at >= ?`,
		id, time.Now().Unix()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read ACME authorization: %w", err)
	}
	return authz, nil
}

// ACMEAuthzsOfOrder returns the authorizations of an order, in the order
// they were created.
func (s *Store) ACMEAuthzsOfOrder(ctx context.Context, orderID string) ([]ACMEAuthz, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+acmeAuthzColumns+` FROM acme_authzs WHERE order_id = ? ORDER BY rowid`, orderID)
	if err != nil {
		return nil, fmt.Errorf("read ACME authorizations: %w", err)
	}
	defer rows.Close()

	var authzs []ACMEAuthz
	for rows.Next() {
		authz, err := scanACMEAuthz(rows)
		if err != nil {
			return nil, fmt.Errorf("read ACME authorizations: %w", err)
		}
		authzs = append(authzs, *authz)
	}
	return authzs, rows.Err()
}

// FinishACMEAuthz sets a pending authorization to valid or invalid, as
// decided by the challenge of the given type. It reports false if the
// authorization was not pending any more: an authorization is decided
// once and then stays as it is.
func (s *Store) FinishACMEAuthz(ctx context.Context, id, status, challenge, errText string) (bool, error) {
	if status != ACMEValid && status != ACMEInvalid {
		return false, fmt.Errorf("an ACME authorization cannot be set to %q", status)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE acme_authzs SET status = ?, error = ?, challenge = ? WHERE id = ? AND status = ?`,
		status, errText, challenge, id, ACMEPending)
	if err != nil {
		return false, fmt.Errorf("update ACME authorization: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("update ACME authorization: %w", err)
	}
	return changed == 1, nil
}

// ChangeACMEAccountKey gives an account a new key. It returns ErrKeyInUse
// if another account has that key.
func (s *Store) ChangeACMEAccountKey(ctx context.Context, id, thumbprint, jwk string) error {
	if other, err := s.ACMEAccountByThumbprint(ctx, thumbprint); err == nil && other.ID != id {
		return ErrKeyInUse
	}
	_, err := s.db.ExecContext(ctx, `UPDATE acme_accounts SET thumbprint = ?, jwk = ? WHERE id = ?`, thumbprint, jwk, id)
	if err != nil {
		// The column is unique: another request took the key meanwhile.
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrKeyInUse
		}
		return fmt.Errorf("change ACME account key: %w", err)
	}
	return nil
}

// ACMEAccountOfCertificate returns the ID of the account whose order got
// the certificate with this serial, or ErrNotFound if ACME did not issue
// it.
func (s *Store) ACMEAccountOfCertificate(ctx context.Context, serial string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT account_id FROM acme_orders WHERE serial = ? AND serial != ''`, serial).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read ACME order: %w", err)
	}
	return id, nil
}

// DeactivateACMEAccount closes an account for good.
func (s *Store) DeactivateACMEAccount(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_accounts SET status = ? WHERE id = ?`, ACMEAccountDeactivated, id)
	if err != nil {
		return fmt.Errorf("deactivate ACME account: %w", err)
	}
	return nil
}
