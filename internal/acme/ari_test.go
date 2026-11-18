// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// The example of RFC 9773, section 4.1.
func TestCertIDOfTheRFC(t *testing.T) {
	aki, _ := hex.DecodeString("69885B6B87464041E1B37B847BA0AE2CDE01C8D4")
	cert := &x509.Certificate{AuthorityKeyId: aki, SerialNumber: big.NewInt(0x87654321)}
	id, err := CertID(cert)
	if err != nil {
		t.Fatal(err)
	}
	const want = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"
	if id != want {
		t.Errorf("CertID = %s, want %s", id, want)
	}
	gotAKI, serial, err := ParseCertID(want)
	if err != nil || string(gotAKI) != string(aki) || serial.Int64() != 0x87654321 {
		t.Errorf("ParseCertID = %x, %v, %v", gotAKI, serial, err)
	}
	for _, bad := range []string{"", "abc", "a.", ".b", "a.b.c", "a==.AIdlQyE", "aYhb.gA"} {
		if _, _, err := ParseCertID(bad); err == nil {
			t.Errorf("ParseCertID(%q) accepted", bad)
		}
	}
}

// renewalInfo asks the server and returns the status and window.
func (e *testEnv) renewalInfo(id string) (status int, start, end time.Time, retryAfter string) {
	e.t.Helper()
	resp, err := e.http.Get(e.url + RenewalInfoPath + "/" + id)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, time.Time{}, time.Time{}, ""
	}
	var info renewalInfoJSON
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		e.t.Fatal(err)
	}
	start, err1 := time.Parse(time.RFC3339, info.SuggestedWindow.Start)
	end, err2 := time.Parse(time.RFC3339, info.SuggestedWindow.End)
	if err1 != nil || err2 != nil {
		e.t.Fatalf("window %+v is not RFC 3339", info.SuggestedWindow)
	}
	if !end.After(start) {
		e.t.Errorf("window ends (%v) before it starts (%v)", end, start)
	}
	return resp.StatusCode, start, end, resp.Header.Get("Retry-After")
}

func (e *testEnv) certID(der []byte) (*x509.Certificate, string) {
	e.t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		e.t.Fatal(err)
	}
	id, err := CertID(cert)
	if err != nil {
		e.t.Fatal(err)
	}
	return cert, id
}

// Renewal information (RFC 9773): advertised in the directory; for a fresh
// certificate a window from two thirds to five sixths of its lifetime, with
// Retry-After; for a revoked one a window ending now; unknown certificates,
// another issuer's serial and malformed IDs are refused.
func TestRenewalInfo(t *testing.T) {
	env := newTestEnv(t)
	client := env.registered()
	certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, id := env.certID(env.issue(client, certKey, "web.example.com"))

	// Advertised in the directory.
	resp, err := env.http.Get(env.url + DirectoryPath)
	if err != nil {
		t.Fatal(err)
	}
	var dir directoryJSON
	json.NewDecoder(resp.Body).Decode(&dir)
	resp.Body.Close()
	if dir.RenewalInfo != env.url+RenewalInfoPath {
		t.Errorf("directory renewalInfo = %q", dir.RenewalInfo)
	}

	// A fresh certificate: from two thirds to five sixths of its lifetime.
	status, start, end, retry := env.renewalInfo(id)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	wantStart := cert.NotBefore.Add(lifetime * 2 / 3)
	wantEnd := cert.NotBefore.Add(lifetime * 5 / 6)
	if start.Sub(wantStart).Abs() > time.Second || end.Sub(wantEnd).Abs() > time.Second {
		t.Errorf("window %v to %v, want %v to %v", start, end, wantStart, wantEnd)
	}
	if retry != "3600" {
		t.Errorf("Retry-After = %q, want 3600", retry)
	}

	// Revoked: renew now. The window ends now and starts before.
	if _, err := env.server.store.Revoke(context.Background(), store.KindX509, store.X509Serial(cert.SerialNumber), 1); err != nil {
		t.Fatal(err)
	}
	_, start, end, _ = env.renewalInfo(id)
	if now := time.Now(); !start.Before(now) || end.After(now.Add(time.Second)) || now.Sub(end) > time.Minute {
		t.Errorf("revoked: window %v to %v, want one ending now", start, end)
	}

	// Not one of this CA's, and not an ID at all.
	other := &x509.Certificate{AuthorityKeyId: cert.AuthorityKeyId, SerialNumber: big.NewInt(12345)}
	otherID, _ := CertID(other)
	if status, _, _, _ := env.renewalInfo(otherID); status != http.StatusNotFound {
		t.Errorf("unknown certificate: status %d, want 404", status)
	}
	wrongIssuer := &x509.Certificate{AuthorityKeyId: []byte("another CA"), SerialNumber: cert.SerialNumber}
	wrongID, _ := CertID(wrongIssuer)
	if status, _, _, _ := env.renewalInfo(wrongID); status != http.StatusNotFound {
		t.Errorf("same serial, other issuer: status %d, want 404", status)
	}
	if status, _, _, _ := env.renewalInfo("not-an-id"); status != http.StatusBadRequest {
		t.Errorf("malformed ID: status %d, want 400", status)
	}
}

// An order that replaces a certificate (RFC 9773): refused for another
// account, without a name in common, or with a malformed ID; accepted for
// the real renewal, which keeps saying what it replaces; a second
// replacement of the same certificate is alreadyReplaced.
func TestOrderReplaces(t *testing.T) {
	env := newTestEnv(t)
	alice := env.registered()
	certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, id := env.certID(env.issue(alice, certKey, "web.example.com"))
	newOrder := env.url + "/acme/new-order"
	order := func(name, replaces string) string {
		return `{"identifiers":[{"type":"dns","value":"` + name + `"}],"replaces":"` + replaces + `"}`
	}

	// Another account may not replace Alice's certificate.
	mallory := env.registered()
	if status, kind := env.rawPost(mallory, newOrder, order("web.example.com", id)); status != http.StatusForbidden || kind != errUnauthorized {
		t.Errorf("other account: %d %s, want 403 unauthorized", status, kind)
	}
	// The order must share a name with the certificate.
	if status, kind := env.rawPost(alice, newOrder, order("api.example.com", id)); status != http.StatusBadRequest || kind != errMalformed {
		t.Errorf("no name in common: %d %s, want 400 malformed", status, kind)
	}
	// An ID that is not one.
	if status, _ := env.rawPost(alice, newOrder, order("web.example.com", "nonsense")); status != http.StatusBadRequest {
		t.Errorf("malformed replaces: status %d, want 400", status)
	}

	// The real renewal: accepted, and "replaces" comes back in the order.
	ctx := context.Background()
	account, err := alice.GetReg(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	resp := env.signedPost(alice.Key, account.URI, newOrder, order("web.example.com", id))
	var got orderJSON
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || got.Replaces != id {
		t.Fatalf("renewal order: status %d, replaces %q; want 201 and %q", resp.StatusCode, got.Replaces, id)
	}
	// Asked again, the order still says so.
	resp = env.signedPost(alice.Key, account.URI, resp.Header.Get("Location"), "")
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if got.Replaces != id {
		t.Errorf("order fetched later: replaces %q, want %q", got.Replaces, id)
	}

	// A second order replacing the same certificate.
	if status, kind := env.rawPost(alice, newOrder, order("web.example.com", id)); status != http.StatusConflict || kind != errAlreadyReplaced {
		t.Errorf("second replacement: %d %s, want 409 alreadyReplaced", status, kind)
	}
}

// signedPost sends a signed request and returns the whole answer.
func (e *testEnv) signedPost(key crypto.Signer, kid, address, payload string) *http.Response {
	e.t.Helper()
	body := e.sign(rawRequest{key: key, kid: kid, nonce: e.nonce(), signedURL: address, payload: payload})
	resp, err := e.http.Post(address, "application/jose+json", strings.NewReader(string(body)))
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}
