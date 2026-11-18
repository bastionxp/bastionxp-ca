// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// This file keeps the list of all certificates the CA has issued. The CA
// writes to it through RecordX509 and RecordSSH (see ca.Recorder). The
// list is what makes it possible to look a certificate up, to revoke it,
// and to tell a certificate of this CA from one that only claims to be.

const certificatesSchema = `
CREATE TABLE IF NOT EXISTS certificates (
	kind       TEXT    NOT NULL,            -- 'x509' or 'ssh'
	serial     TEXT    NOT NULL,            -- x509: hex, lower case; ssh: decimal
	template   TEXT    NOT NULL,
	subject    TEXT    NOT NULL,            -- x509: common name; ssh: key ID
	names      TEXT    NOT NULL,            -- JSON list
	body       TEXT    NOT NULL,            -- the certificate itself, as text
	issued_at  INTEGER NOT NULL,
	not_after  INTEGER NOT NULL,
	revoked_at INTEGER NOT NULL DEFAULT 0,  -- 0: not revoked
	reason     INTEGER NOT NULL DEFAULT 0,
	protocol   TEXT    NOT NULL DEFAULT '', -- how it was obtained: api, acme or scep
	PRIMARY KEY (kind, serial)
);
`

// Kinds of certificates.
const (
	KindX509 = "x509"
	KindSSH  = "ssh"
)

// keepExpiredFor is how long a certificate stays in the list after it has
// expired, for looking things up afterwards.
const keepExpiredFor = 90 * 24 * time.Hour

// ErrAlreadyRevoked is returned when a certificate is revoked a second time.
var ErrAlreadyRevoked = errors.New("the certificate is already revoked")

// Certificate is one entry of the list.
type Certificate struct {
	Kind     string
	Serial   string
	Template string
	// Subject is the common name of an X.509 certificate or the key ID
	// of an SSH certificate.
	Subject string
	// Names are the DNS names, IP addresses and email addresses of an
	// X.509 certificate, or the principals of an SSH certificate.
	Names []string
	// Body is the certificate: PEM for X.509, one line for SSH.
	Body     string
	IssuedAt time.Time
	NotAfter time.Time
	// RevokedAt is the zero time for a certificate that is not revoked.
	RevokedAt time.Time
	Reason    int
	// Protocol is how the certificate was obtained: "api", "acme" or
	// "scep" (see the ca.Protocol constants); empty for the CA's own.
	Protocol string
}

// Revoked reports whether the certificate has been revoked.
func (c *Certificate) Revoked() bool { return !c.RevokedAt.IsZero() }

// X509Serial returns a serial number the way the list stores it.
func X509Serial(serial *big.Int) string { return serial.Text(16) }

// ParseX509Serial reads a serial number as people write it: hex, with or
// without colons, upper or lower case, with or without "0x".
func ParseX509Serial(text string) (string, error) {
	cleaned := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(text), ":", ""))
	cleaned = strings.TrimPrefix(cleaned, "0x")
	serial, ok := new(big.Int).SetString(cleaned, 16)
	if !ok || serial.Sign() <= 0 {
		return "", fmt.Errorf("%q is not a certificate serial number (hex digits)", text)
	}
	return X509Serial(serial), nil
}

// RecordX509 adds an X.509 certificate to the list. It is part of the
// ca.Recorder interface.
func (s *Store) RecordX509(cert *x509.Certificate, template, protocol string) error {
	var names []string
	names = append(names, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	names = append(names, cert.EmailAddresses...)
	return s.record(Certificate{
		Kind:     KindX509,
		Serial:   X509Serial(cert.SerialNumber),
		Template: template,
		Subject:  cert.Subject.CommonName,
		Names:    names,
		Body:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		IssuedAt: cert.NotBefore,
		NotAfter: cert.NotAfter,
		Protocol: protocol,
	})
}

// RecordSSH adds an SSH certificate to the list. It is part of the
// ca.Recorder interface.
func (s *Store) RecordSSH(cert *ssh.Certificate, template string) error {
	return s.record(Certificate{
		Kind:     KindSSH,
		Serial:   SSHSerial(cert.Serial),
		Template: template,
		Subject:  cert.KeyId,
		Names:    cert.ValidPrincipals,
		Body:     string(ssh.MarshalAuthorizedKey(cert)),
		IssuedAt: time.Unix(int64(cert.ValidAfter), 0),
		NotAfter: time.Unix(int64(cert.ValidBefore), 0),
		Protocol: "api", // SSH certificates come only from the API
	})
}

func (s *Store) record(cert Certificate) error {
	names, err := json.Marshal(cert.Names)
	if err != nil {
		return err
	}
	ctx := context.Background()

	// Tidy up certificates that expired long ago.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM certificates WHERE not_after < ?`,
		time.Now().Add(-keepExpiredFor).Unix()); err != nil {
		return fmt.Errorf("remove old certificates: %w", err)
	}

	// A plain INSERT: a serial number that is already there is an
	// error. Serial numbers are random, so that never happens by
	// accident, and it must not happen at all.
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO certificates (kind, serial, template, subject, names, body, issued_at, not_after, protocol)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cert.Kind, cert.Serial, cert.Template, cert.Subject, string(names), cert.Body,
		cert.IssuedAt.Unix(), cert.NotAfter.Unix(), cert.Protocol)
	if err != nil {
		return fmt.Errorf("record certificate: %w", err)
	}
	return nil
}

const certificateColumns = `kind, serial, template, subject, names, body, issued_at, not_after, revoked_at, reason, protocol`

func scanCertificate(row interface{ Scan(...any) error }) (*Certificate, error) {
	var cert Certificate
	var names string
	var issuedAt, notAfter, revokedAt int64
	err := row.Scan(&cert.Kind, &cert.Serial, &cert.Template, &cert.Subject, &names, &cert.Body,
		&issuedAt, &notAfter, &revokedAt, &cert.Reason, &cert.Protocol)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(names), &cert.Names); err != nil {
		return nil, err
	}
	cert.IssuedAt = time.Unix(issuedAt, 0)
	cert.NotAfter = time.Unix(notAfter, 0)
	if revokedAt != 0 {
		cert.RevokedAt = time.Unix(revokedAt, 0)
	}
	return &cert, nil
}

// Certificate returns the certificate of the given kind and serial
// number, or ErrNotFound.
func (s *Store) Certificate(ctx context.Context, kind, serial string) (*Certificate, error) {
	cert, err := scanCertificate(s.db.QueryRowContext(ctx,
		`SELECT `+certificateColumns+` FROM certificates WHERE kind = ? AND serial = ?`, kind, serial))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	return cert, nil
}

// Certificates returns the list, newest first. With onlyRevoked it
// returns only the revoked ones.
func (s *Store) Certificates(ctx context.Context, onlyRevoked bool) ([]Certificate, error) {
	query := `SELECT ` + certificateColumns + ` FROM certificates`
	if onlyRevoked {
		query += ` WHERE revoked_at != 0`
	}
	rows, err := s.db.QueryContext(ctx, query+` ORDER BY issued_at DESC, rowid DESC`)
	if err != nil {
		return nil, fmt.Errorf("read certificates: %w", err)
	}
	defer rows.Close()

	var certs []Certificate
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, fmt.Errorf("read certificates: %w", err)
		}
		certs = append(certs, *cert)
	}
	return certs, rows.Err()
}

// Revoke marks a certificate as revoked, from now on. It returns
// ErrNotFound for a serial number that is not in the list and
// ErrAlreadyRevoked for one that was revoked before.
//
// A revocation is never taken back: someone may already have acted on it.
//
// A revoked X.509 certificate goes on the CRL and gets "revoked" from
// OCSP. A revoked SSH certificate can no longer be renewed; SSH servers
// are not told (see the revocation page of the documentation).
func (s *Store) Revoke(ctx context.Context, kind, serial string, reason int) (*Certificate, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE certificates SET revoked_at = ?, reason = ? WHERE kind = ? AND serial = ? AND revoked_at = 0`,
		time.Now().Unix(), reason, kind, serial)
	if err != nil {
		return nil, fmt.Errorf("revoke certificate: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("revoke certificate: %w", err)
	}
	cert, err := s.Certificate(ctx, kind, serial)
	if err != nil {
		return nil, err // ErrNotFound: there was nothing to revoke
	}
	if changed == 0 {
		return cert, ErrAlreadyRevoked
	}
	return cert, nil
}

// RevokeX509 revokes an X.509 certificate. See Revoke.
func (s *Store) RevokeX509(ctx context.Context, serial string, reason int) (*Certificate, error) {
	return s.Revoke(ctx, KindX509, serial, reason)
}

// SSHSerial returns an SSH serial number the way the list stores it.
func SSHSerial(serial uint64) string { return strconv.FormatUint(serial, 10) }

// ParseSSHSerial reads an SSH serial number: a decimal number, as
// "ssh-keygen -L" prints it.
func ParseSSHSerial(text string) (string, error) {
	serial, err := strconv.ParseUint(strings.TrimSpace(text), 10, 64)
	if err != nil {
		return "", fmt.Errorf("%q is not an SSH certificate serial number (a decimal number)", text)
	}
	return SSHSerial(serial), nil
}

// RevokedX509 returns the revoked X.509 certificates that have not
// expired yet: what belongs on a CRL. An expired certificate is not
// trusted by anybody anyway, so it can leave the list.
func (s *Store) RevokedX509(ctx context.Context) ([]Certificate, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+certificateColumns+` FROM certificates
		 WHERE kind = ? AND revoked_at != 0 AND not_after >= ? ORDER BY revoked_at, rowid`,
		KindX509, time.Now().Unix())
	if err != nil {
		return nil, fmt.Errorf("read revoked certificates: %w", err)
	}
	defer rows.Close()

	var certs []Certificate
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, fmt.Errorf("read revoked certificates: %w", err)
		}
		certs = append(certs, *cert)
	}
	return certs, rows.Err()
}

// CertificateCount is the number of certificates of one template in one
// state.
type CertificateCount struct {
	Template string
	State    string // "valid", "expired" or "revoked"
	Count    int
}

// CountCertificates counts the certificates by template and state, for
// the metrics.
func (s *Store) CountCertificates(ctx context.Context, now time.Time) ([]CertificateCount, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT template,
		       CASE WHEN revoked_at != 0 THEN 'revoked'
		            WHEN not_after < ? THEN 'expired'
		            ELSE 'valid' END AS state,
		       COUNT(*)
		  FROM certificates GROUP BY template, state`, now.Unix())
	if err != nil {
		return nil, fmt.Errorf("count certificates: %w", err)
	}
	defer rows.Close()
	var counts []CertificateCount
	for rows.Next() {
		var c CertificateCount
		if err := rows.Scan(&c.Template, &c.State, &c.Count); err != nil {
			return nil, fmt.Errorf("count certificates: %w", err)
		}
		counts = append(counts, c)
	}
	return counts, rows.Err()
}

// RevocationState is a cheap summary of the revocations: it changes
// whenever a certificate is revoked (or a revoked one is forgotten after
// it expired). The server watches it to know when its cached CRL and OCSP
// answers are out of date.
type RevocationState struct {
	Count  int
	Latest int64 // the newest revoked_at, Unix seconds
}

// RevocationState returns the current summary.
func (s *Store) RevocationState(ctx context.Context) (RevocationState, error) {
	var st RevocationState
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(MAX(revoked_at), 0) FROM certificates WHERE revoked_at != 0`).Scan(&st.Count, &st.Latest)
	if err != nil {
		return st, fmt.Errorf("read revocations: %w", err)
	}
	return st, nil
}

// RevokedSince returns the certificates revoked at or after since,
// oldest first.
func (s *Store) RevokedSince(ctx context.Context, since time.Time) ([]Certificate, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+certificateColumns+` FROM certificates
		 WHERE revoked_at != 0 AND revoked_at >= ? ORDER BY revoked_at, rowid`, since.Unix())
	if err != nil {
		return nil, fmt.Errorf("read revocations: %w", err)
	}
	defer rows.Close()
	var certs []Certificate
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, fmt.Errorf("read revocations: %w", err)
		}
		certs = append(certs, *cert)
	}
	return certs, rows.Err()
}
