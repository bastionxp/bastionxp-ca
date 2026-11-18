// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
	"time"

	acmeclient "golang.org/x/crypto/acme"

	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// issue gets a certificate for name with client, for the key certKey,
// and returns it (DER).
func (e *testEnv) issue(client *acmeclient.Client, certKey *ecdsa.PrivateKey, name string) []byte {
	e.t.Helper()
	ctx := context.Background()
	order, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs(name))
	if err != nil {
		e.t.Fatal(err)
	}
	order = e.prove(client, order)
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, newCSR(e.t, certKey, name, name), true)
	if err != nil {
		e.t.Fatal(err)
	}
	return chain[0]
}

func (e *testEnv) revokedReason(der []byte) (bool, int) {
	e.t.Helper()
	cert, _ := x509.ParseCertificate(der)
	record, err := e.server.store.Certificate(context.Background(), "x509", store.X509Serial(cert.SerialNumber))
	if err != nil {
		e.t.Fatal(err)
	}
	return record.Revoked(), record.Reason
}

// Anyone with the certificate's key may revoke it over ACME, without an
// account; a second revocation is alreadyRevoked.
func TestRevokeWithTheCertificateKey(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	certKey := mustKey(t)
	der := env.issue(env.registered(), certKey, "web.example.com")

	// Anybody with the certificate's key may revoke it, without the
	// account: here a client that has never registered.
	stranger := env.newClient()
	if err := stranger.RevokeCert(ctx, certKey, der, acmeclient.CRLReasonKeyCompromise); err != nil {
		t.Fatal(err)
	}
	if revoked, reason := env.revokedReason(der); !revoked || reason != 1 {
		t.Errorf("revoked %v, reason %d; want revoked for key compromise", revoked, reason)
	}
	// A second time: "alreadyRevoked" (which the client takes as done).
	err := stranger.RevokeCert(ctx, certKey, der, acmeclient.CRLReasonKeyCompromise)
	if err != nil {
		t.Errorf("second revocation: %v", err)
	}
	status, kind := env.send(env.url+"/acme/revoke-cert", env.signRevoke(certKey, der, 0))
	if status != 400 || kind != "alreadyRevoked" {
		t.Errorf("second revocation: %d %s, want 400 alreadyRevoked", status, kind)
	}
}

// The account that ordered a certificate may revoke it; another account, or
// another key, may not; a reason the CA does not use is refused.
func TestRevokeByTheAccount(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	owner := env.registered()
	der := env.issue(owner, mustKey(t), "web.example.com")

	// Another account may not.
	other := env.registered()
	wantProblem(t, other.RevokeCert(ctx, nil, der, acmeclient.CRLReasonSuperseded), "unauthorized")
	// Nor another key that is not the certificate's.
	wantProblem(t, other.RevokeCert(ctx, mustKey(t), der, acmeclient.CRLReasonSuperseded), "unauthorized")
	if revoked, _ := env.revokedReason(der); revoked {
		t.Fatal("revoked by somebody else")
	}

	// A reason the CA does not use.
	wantProblem(t, owner.RevokeCert(ctx, nil, der, acmeclient.CRLReasonCACompromise), "badRevocationReason")

	if err := owner.RevokeCert(ctx, nil, der, acmeclient.CRLReasonSuperseded); err != nil {
		t.Fatal(err)
	}
	if revoked, reason := env.revokedReason(der); !revoked || reason != 4 {
		t.Errorf("revoked %v, reason %d; want revoked as superseded", revoked, reason)
	}
}

// A certificate this CA did not issue, or a forged one with the serial
// of a real one, is refused.
func TestRevokeOnlyOwnCertificates(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	client := env.registered()
	real := env.issue(client, mustKey(t), "web.example.com")
	realCert, _ := x509.ParseCertificate(real)

	key := mustKey(t)
	template := &x509.Certificate{
		SerialNumber: new(big.Int).Set(realCert.SerialNumber), // same serial
		Subject:      pkix.Name{CommonName: "web.example.com"},
		DNSNames:     []string{"web.example.com"},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	forged, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	wantProblem(t, client.RevokeCert(ctx, key, forged, acmeclient.CRLReasonUnspecified), "malformed")
	if revoked, _ := env.revokedReason(real); revoked {
		t.Error("the real certificate was revoked through a forged one")
	}
}

// A deactivated account can neither order nor revoke, and its key opens
// neither it nor a new account; its certificate stays valid and can still be
// revoked with its own key.
func TestDeactivateAccount(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	client := env.registered()
	certKey := mustKey(t)
	der := env.issue(client, certKey, "web.example.com")

	if err := client.DeactivateReg(ctx); err != nil {
		t.Fatal(err)
	}
	// The account can do nothing more.
	_, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs("web.example.com"))
	wantProblem(t, err, "unauthorized")
	wantProblem(t, client.RevokeCert(ctx, nil, der, acmeclient.CRLReasonUnspecified), "unauthorized")
	// Its key opens neither it nor a new account.
	again := &acmeclient.Client{Key: client.Key, DirectoryURL: client.DirectoryURL, HTTPClient: env.http}
	_, err = again.Register(ctx, &acmeclient.Account{}, acmeclient.AcceptTOS)
	wantProblem(t, err, "unauthorized")
	_, err = again.GetReg(ctx, "")
	wantProblem(t, err, "unauthorized")

	// Its certificate stays valid, and its own key can still revoke it.
	if revoked, _ := env.revokedReason(der); revoked {
		t.Error("closing the account revoked its certificate")
	}
	if err := env.newClient().RevokeCert(ctx, certKey, der, acmeclient.CRLReasonCessationOfOperation); err != nil {
		t.Errorf("revoking with the certificate key after the account was closed: %v", err)
	}
}

// signRevoke builds a revoke-cert request signed with the certificate's key.
func (e *testEnv) signRevoke(certKey *ecdsa.PrivateKey, der []byte, reason int) []byte {
	address := e.url + "/acme/revoke-cert"
	payload := fmt.Sprintf(`{"certificate":%q,"reason":%d}`, base64.RawURLEncoding.EncodeToString(der), reason)
	return e.sign(rawRequest{key: certKey, nonce: e.nonce(), signedURL: address, payload: payload})
}

// RFC 8555 section 11.1: no certificate may carry the key of any ACME
// account, not only the requesting one's. Reusing a certificate key in a
// new order (a renewal that keeps its key) is allowed: the RFC sets no
// rule for it.
func TestCertificateKeys(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	other := env.registered()
	client := env.registered()

	order, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs("web.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	order = env.prove(client, order)
	otherKey := other.Key.(*ecdsa.PrivateKey)
	_, _, err = client.CreateOrderCert(ctx, order.FinalizeURL, newCSR(t, otherKey, "web.example.com", "web.example.com"), true)
	wantProblem(t, err, "badCSR")

	// The same certificate key in two orders: both are issued.
	certKey := mustKey(t)
	first := env.issue(client, certKey, "web.example.com")
	second := env.issue(client, certKey, "web.example.com")
	a, _ := x509.ParseCertificate(first)
	b, _ := x509.ParseCertificate(second)
	if a.SerialNumber.Cmp(b.SerialNumber) == 0 || !samePublicKey(a.PublicKey, b.PublicKey) {
		t.Error("want two certificates for the same key")
	}
}
