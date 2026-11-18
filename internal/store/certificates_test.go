// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// newTestX509 returns a self-signed certificate with the given serial
// number. Who signed it does not matter to the store.
func newTestX509(t *testing.T, serial int64, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:   big.NewInt(serial),
		Subject:        pkix.Name{CommonName: "web.example.com"},
		DNSNames:       []string{"web.example.com", "www.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.5")},
		EmailAddresses: []string{"admin@example.com"},
		NotBefore:      time.Now().Add(-time.Hour).Truncate(time.Second),
		NotAfter:       notAfter.Truncate(time.Second),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// A recorded TLS certificate reads back with its profile, subject, names,
// PEM body and dates, not revoked; an unknown serial number, or the same
// number as an SSH certificate, is not found.
func TestRecordAndReadX509(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	cert := newTestX509(t, 0xABCDEF, time.Now().Add(24*time.Hour))

	if err := s.RecordX509(cert, "tls-server", "api"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Certificate(ctx, KindX509, "abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if got.Template != "tls-server" || got.Subject != "web.example.com" {
		t.Errorf("template %q, subject %q", got.Template, got.Subject)
	}
	wantNames := []string{"web.example.com", "www.example.com", "10.0.0.5", "admin@example.com"}
	if !reflect.DeepEqual(got.Names, wantNames) {
		t.Errorf("names = %v, want %v", got.Names, wantNames)
	}
	if !strings.HasPrefix(got.Body, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("body = %q", got.Body)
	}
	if !got.NotAfter.Equal(cert.NotAfter) || !got.IssuedAt.Equal(cert.NotBefore) {
		t.Errorf("issued %s, ends %s", got.IssuedAt, got.NotAfter)
	}
	if got.Revoked() {
		t.Error("a new certificate is revoked")
	}

	if _, err := s.Certificate(ctx, KindX509, "123456"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown serial: error = %v, want ErrNotFound", err)
	}
	// The same number as an SSH certificate is another certificate.
	if _, err := s.Certificate(ctx, KindSSH, "abcdef"); !errors.Is(err, ErrNotFound) {
		t.Errorf("other kind: error = %v, want ErrNotFound", err)
	}
}

// Two certificates must never share a serial number. If the CA ever made
// one twice, the second must not be recorded, and so not be issued.
func TestRecordRefusesASerialNumberTwice(t *testing.T) {
	s, _ := openTestStore(t)
	notAfter := time.Now().Add(time.Hour)
	if err := s.RecordX509(newTestX509(t, 42, notAfter), "tls-server", "api"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordX509(newTestX509(t, 42, notAfter), "tls-server", "api"); err == nil {
		t.Error("a second certificate with the same serial number was recorded")
	}
}

// A recorded SSH certificate reads back with its principals, body and end,
// even with the largest serial number an SSH certificate can have.
func TestRecordSSH(t *testing.T) {
	s, _ := openTestStore(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(pub)
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(caKey)
	now := time.Now().Truncate(time.Second)
	cert := &ssh.Certificate{
		Key: sshPub, Serial: 18446744073709551615, CertType: ssh.UserCert, KeyId: "alice-abc",
		ValidPrincipals: []string{"alice", "deploy"},
		ValidAfter:      uint64(now.Unix()), ValidBefore: uint64(now.Add(16 * time.Hour).Unix()),
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	if err := s.RecordSSH(cert, "ssh-user"); err != nil {
		t.Fatal(err)
	}
	// The largest serial number an SSH certificate can have survives.
	got, err := s.Certificate(context.Background(), KindSSH, "18446744073709551615")
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "alice-abc" || !reflect.DeepEqual(got.Names, []string{"alice", "deploy"}) || got.Template != "ssh-user" {
		t.Errorf("read back %+v", got)
	}
	if !strings.Contains(got.Body, "-cert-v01@openssh.com") {
		t.Errorf("body = %q, want an SSH certificate line", got.Body)
	}
	if !got.NotAfter.Equal(now.Add(16 * time.Hour)) {
		t.Errorf("ends %s", got.NotAfter)
	}
}

// Revoking a TLS certificate records the time and reason; a second
// revocation is refused and changes neither; an unknown serial number is not
// found.
func TestRevokeX509(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	if err := s.RecordX509(newTestX509(t, 0x1001, time.Now().Add(time.Hour)), "tls-server", "api"); err != nil {
		t.Fatal(err)
	}

	before := time.Now().Add(-time.Second)
	cert, err := s.RevokeX509(ctx, "1001", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.Revoked() || cert.Reason != 1 || cert.RevokedAt.Before(before) {
		t.Errorf("after revoking: %+v", cert)
	}

	// A second time changes nothing: neither the time nor the reason.
	again, err := s.RevokeX509(ctx, "1001", 5)
	if !errors.Is(err, ErrAlreadyRevoked) {
		t.Errorf("second revocation: error = %v, want ErrAlreadyRevoked", err)
	}
	if again == nil || again.Reason != 1 || !again.RevokedAt.Equal(cert.RevokedAt) {
		t.Errorf("the second revocation changed the record: %+v", again)
	}

	if _, err := s.RevokeX509(ctx, "9999", 0); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown serial: error = %v, want ErrNotFound", err)
	}
}

// Revoking a TLS serial number does not revoke an SSH certificate with the
// same number.
func TestRevokeX509DoesNotTouchSSHCertificates(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	if err := s.record(Certificate{Kind: KindSSH, Serial: "1001", Template: "ssh-user", Subject: "a",
		Body: "x", IssuedAt: time.Now(), NotAfter: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeX509(ctx, "1001", 0); !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
	got, _ := s.Certificate(ctx, KindSSH, "1001")
	if got.Revoked() {
		t.Error("an SSH certificate was revoked by an X.509 serial number")
	}
}

// The CRL gets revoked certificates that have not expired; the list has
// every certificate, and the revoked list includes expired revoked ones.
func TestRevokedX509AndList(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	soon := time.Now().Add(time.Hour)

	for _, serial := range []int64{1, 2, 3} {
		if err := s.RecordX509(newTestX509(t, serial, soon), "tls-server", "api"); err != nil {
			t.Fatal(err)
		}
	}
	// One that has expired, but not long enough ago to be tidied away.
	if err := s.RecordX509(newTestX509(t, 4, time.Now().Add(-time.Minute)), "tls-server", "api"); err != nil {
		t.Fatal(err)
	}
	for _, serial := range []string{"2", "4"} {
		if _, err := s.RevokeX509(ctx, serial, 0); err != nil {
			t.Fatal(err)
		}
	}

	// What goes on the CRL: revoked, and not yet expired.
	revoked, err := s.RevokedX509(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 1 || revoked[0].Serial != "2" {
		t.Errorf("for the CRL: %d certificates, want only serial 2", len(revoked))
	}

	all, err := s.Certificates(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Errorf("the list has %d certificates, want 4", len(all))
	}
	onlyRevoked, err := s.Certificates(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(onlyRevoked) != 2 {
		t.Errorf("the revoked list has %d certificates, want 2 (the expired one too)", len(onlyRevoked))
	}
}

// A certificate that expired long ago is removed when the next one is
// recorded.
func TestOldCertificatesAreTidiedAway(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	long := time.Now().Add(-keepExpiredFor - time.Hour)
	if err := s.record(Certificate{Kind: KindX509, Serial: "old", Template: "tls-server",
		Body: "x", IssuedAt: long.Add(-time.Hour), NotAfter: long}); err != nil {
		t.Fatal(err)
	}
	// The next certificate tidies it away.
	if err := s.RecordX509(newTestX509(t, 7, time.Now().Add(time.Hour)), "tls-server", "api"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Certificate(ctx, KindX509, "old"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a certificate that expired long ago is still there: %v", err)
	}
}

// TLS serial numbers are read in lower or upper case, with colons, 0x,
// spaces or leading zeros; anything else is refused.
func TestParseX509Serial(t *testing.T) {
	good := map[string]string{
		"abcdef":        "abcdef",
		"ABCDEF":        "abcdef",
		"AB:CD:EF":      "abcdef",
		"0xabcdef":      "abcdef",
		"  00abcdef \n": "abcdef", // leading zeros do not change the number
		"1":             "1",
	}
	for text, want := range good {
		got, err := ParseX509Serial(text)
		if err != nil || got != want {
			t.Errorf("ParseX509Serial(%q) = %q, %v; want %q", text, got, err, want)
		}
	}
	for _, text := range []string{"", "0", "-1", "xyz", "12 34", "abc; DROP TABLE certificates"} {
		if got, err := ParseX509Serial(text); err == nil {
			t.Errorf("ParseX509Serial(%q) = %q, want an error", text, got)
		}
	}
}

// Revoking an SSH certificate is recorded, once, and does not put it on the
// CRL.
func TestRevokeSSH(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	if err := s.record(Certificate{Kind: KindSSH, Serial: "1001", Template: "ssh-host", Subject: "web1",
		Body: "x", IssuedAt: time.Now(), NotAfter: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	cert, err := s.Revoke(ctx, KindSSH, "1001", 1)
	if err != nil || !cert.Revoked() {
		t.Fatalf("revoke: %+v, %v", cert, err)
	}
	if _, err := s.Revoke(ctx, KindSSH, "1001", 1); !errors.Is(err, ErrAlreadyRevoked) {
		t.Errorf("second revocation: error = %v", err)
	}
	// An SSH revocation does not end up on the CRL.
	revoked, err := s.RevokedX509(ctx)
	if err != nil || len(revoked) != 0 {
		t.Errorf("for the CRL: %d certificates, error %v; want none", len(revoked), err)
	}
}

// SSH serial numbers are read as decimal up to the largest 64-bit number,
// with spaces or leading zeros; negative, non-numeric, too large or two
// numbers are refused.
func TestParseSSHSerial(t *testing.T) {
	for text, want := range map[string]string{"1001": "1001", " 18446744073709551615\n": "18446744073709551615", "007": "7"} {
		if got, err := ParseSSHSerial(text); err != nil || got != want {
			t.Errorf("ParseSSHSerial(%q) = %q, %v; want %q", text, got, err, want)
		}
	}
	for _, text := range []string{"", "-1", "abc", "18446744073709551616", "1 2"} {
		if got, err := ParseSSHSerial(text); err == nil {
			t.Errorf("ParseSSHSerial(%q) = %q, want an error", text, got)
		}
	}
}
