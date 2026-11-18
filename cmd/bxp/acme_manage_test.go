// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// issueForTest gets a certificate from the test CA over ACME and returns
// the paths of its certificate and key.
func issueForTest(t *testing.T, testCA *testCA, names ...string) (certFile, keyFile string) {
	t.Helper()
	address := freeAddress(t)
	testCA.acme.set(address)
	outDir := t.TempDir()
	if err := runACME(context.Background(), io.Discard, testCA.acmeConn(), acmeOptions{names: names, outDir: outDir, httpAddress: address}); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(outDir, names[0]+".crt"), filepath.Join(outDir, names[0]+".key")
}

// bxp acme renew: a fresh certificate is not due and stays; forced, a new
// key and certificate for the same names, the --exec command run, and the
// account next to the certificate used again.
func TestACMERenew(t *testing.T) {
	testCA := startTestCA(t)
	certFile, keyFile := issueForTest(t, testCA, "web.example.com", "api.example.com")
	before, _ := tls.LoadX509KeyPair(certFile, keyFile)
	address := freeAddress(t)
	testCA.acme.set(address)
	opts := acmeRenewOptions{cert: certFile, key: keyFile, httpAddress: address}

	// A fresh certificate is not due: nothing changes.
	var out bytes.Buffer
	if err := runACMERenew(context.Background(), &out, io.Discard, testCA.acmeConn(), opts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Not yet") {
		t.Errorf("output:\n%s", out.String())
	}
	if same, _ := tls.LoadX509KeyPair(certFile, keyFile); !bytes.Equal(same.Certificate[0], before.Certificate[0]) {
		t.Error("a certificate that was not due was replaced")
	}

	// Forced: a new key and certificate, for the same names, and --exec runs.
	opts.force = true
	marker := filepath.Join(t.TempDir(), "reloaded")
	opts.exec = "touch " + marker
	out.Reset()
	if err := runACMERenew(context.Background(), &out, io.Discard, testCA.acmeConn(), opts); err != nil {
		t.Fatal(err)
	}
	after, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(after.Certificate[0], before.Certificate[0]) {
		t.Error("the certificate was not replaced")
	}
	oldLeaf, _ := x509.ParseCertificate(before.Certificate[0])
	newLeaf, _ := x509.ParseCertificate(after.Certificate[0])
	if sameKey(oldLeaf.PublicKey, newLeaf.PublicKey) {
		t.Error("the renewal kept the old key")
	}
	if !slices.Equal(newLeaf.DNSNames, oldLeaf.DNSNames) {
		t.Errorf("names %v, want %v", newLeaf.DNSNames, oldLeaf.DNSNames)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("--exec did not run: %v", err)
	}
	// The account next to the certificate was used again, not a new one.
	if _, err := os.Stat(filepath.Join(filepath.Dir(certFile), accountKeyFile)); err != nil {
		t.Error(err)
	}
}

// bxp acme renew refuses missing files, the wrong key, and the dns-01
// challenge.
func TestACMERenewChecks(t *testing.T) {
	conn := connection{url: "https://127.0.0.1:1", prompt: io.Discard}
	testCA := startTestCA(t)
	certFile, _ := issueForTest(t, testCA, "web.example.com")
	_, otherKey := issueForTest(t, testCA, "api.example.com")
	for _, tt := range []struct {
		name    string
		opts    acmeRenewOptions
		wantErr string
	}{
		{"no files", acmeRenewOptions{}, "--cert"},
		{"wrong key", acmeRenewOptions{cert: certFile, key: otherKey, force: true}, "is not the key"},
		{"dns-01", acmeRenewOptions{cert: certFile, key: otherKey, challenge: "dns-01"}, "--challenge"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := runACMERenew(context.Background(), io.Discard, io.Discard, conn, tt.opts)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// bxp acme rollover-key replaces the account key (mode 600, no .new file
// left) and the new key works; a leftover from an earlier rollover stops it,
// the key unchanged.
func TestACMERolloverKey(t *testing.T) {
	testCA := startTestCA(t)
	certFile, keyFile := issueForTest(t, testCA, "web.example.com")
	accountKey := filepath.Join(filepath.Dir(certFile), accountKeyFile)
	before, _ := os.ReadFile(accountKey)

	var out bytes.Buffer
	if err := runACMERollover(context.Background(), &out, testCA.acmeConn(), acmeAccount{accountKey: accountKey}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(accountKey)
	if bytes.Equal(before, after) {
		t.Fatal("the account key file was not replaced")
	}
	if info, _ := os.Stat(accountKey); info.Mode().Perm() != 0o600 {
		t.Errorf("account key mode = %o, want 600", info.Mode().Perm())
	}
	if _, err := os.Stat(accountKey + ".new"); err == nil {
		t.Error("the .new file was left behind")
	}
	// The new key works.
	address := freeAddress(t)
	testCA.acme.set(address)
	if err := runACMERenew(context.Background(), io.Discard, io.Discard, testCA.acmeConn(),
		acmeRenewOptions{cert: certFile, key: keyFile, force: true, httpAddress: address}); err != nil {
		t.Fatalf("renewal with the new account key: %v", err)
	}

	// A leftover from an earlier rollover stops it: it may be the real key.
	if err := os.WriteFile(accountKey+".new", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runACMERollover(context.Background(), io.Discard, testCA.acmeConn(), acmeAccount{accountKey: accountKey})
	if err == nil || !strings.Contains(err.Error(), "earlier rollover") {
		t.Errorf("error = %v", err)
	}
	if now, _ := os.ReadFile(accountKey); !bytes.Equal(now, after) {
		t.Error("the account key changed")
	}
}

// isRevoked looks a certificate up in the CA's database, as "bxp list
// certificates" does.
func isRevoked(t *testing.T, testCA *testCA, certFile string) (bool, int) {
	t.Helper()
	leaf, err := readLeaf(certFile)
	if err != nil {
		t.Fatal(err)
	}
	db, err := openStore(testCA.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	record, err := db.Certificate(context.Background(), "x509", serialHex(leaf))
	if err != nil {
		t.Fatal(err)
	}
	return record.Revoked(), record.Reason
}

// Revocation over ACME on BastionXP CA's own CA: by the account, and with the
// certificate's key.
func TestACMERevokeOnBastionXPCA(t *testing.T) {
	testCA := startTestCA(t)
	byAccount, _ := issueForTest(t, testCA, "web.example.com")
	byKeyCert, byKeyKey := issueForTest(t, testCA, "api.example.com")

	var out bytes.Buffer
	if err := runACMERevoke(context.Background(), &out, testCA.acmeConn(), acmeRevokeOptions{cert: byAccount, reason: "superseded"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Revoked") {
		t.Errorf("output:\n%s", out.String())
	}
	if revoked, reason := isRevoked(t, testCA, byAccount); !revoked || reason != 4 {
		t.Errorf("by the account: revoked %v, reason %d", revoked, reason)
	}
	// With the certificate's key: no account key is needed.
	if err := runACMERevoke(context.Background(), io.Discard, testCA.acmeConn(), acmeRevokeOptions{
		cert: byKeyCert, key: byKeyKey, reason: "key-compromise", accountKey: filepath.Join(t.TempDir(), "none.key"),
	}); err != nil {
		t.Fatal(err)
	}
	if revoked, reason := isRevoked(t, testCA, byKeyCert); !revoked || reason != 1 {
		t.Errorf("with the key: revoked %v, reason %d", revoked, reason)
	}
}

// bxp acme deactivate closes the account: its key can no longer get
// certificates, and its certificates are not revoked.
func TestACMEDeactivateOnBastionXPCA(t *testing.T) {
	testCA := startTestCA(t)
	certFile, _ := issueForTest(t, testCA, "web.example.com")
	accountKey := filepath.Join(filepath.Dir(certFile), accountKeyFile)

	var out bytes.Buffer
	if err := runACMEDeactivate(context.Background(), &out, testCA.acmeConn(), acmeAccount{accountKey: accountKey}, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Closed") {
		t.Errorf("output:\n%s", out.String())
	}
	// The key is of no further use.
	address := freeAddress(t)
	testCA.acme.set(address)
	err := runACME(context.Background(), io.Discard, testCA.acmeConn(),
		acmeOptions{names: []string{"web.example.com"}, outDir: t.TempDir(), accountKey: accountKey, httpAddress: address})
	if err == nil || !strings.Contains(err.Error(), "deactivated") {
		t.Errorf("issue with a closed account: error = %v", err)
	}
	if revoked, _ := isRevoked(t, testCA, certFile); revoked {
		t.Error("closing the account revoked its certificate")
	}
}

// fakeACME is an ACME server that does what BastionXP CA's does not: revoke
// and close accounts. It records what it was asked.
type fakeACME struct {
	server *httptest.Server
	root   string // its certificate, as a root file

	mu          sync.Mutex
	revocations []fakeRevocation
	deactivated bool
}

type fakeRevocation struct {
	byKey  *jose.JSONWebKey // the key in the request, or nil if signed by the account
	kid    string
	cert   []byte
	reason int
}

func startFakeACME(t *testing.T) *fakeACME {
	f := &fakeACME{}
	mux := http.NewServeMux()
	f.server = httptest.NewTLSServer(mux)
	t.Cleanup(f.server.Close)
	url := f.server.URL
	mux.HandleFunc("/dir", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce": url + "/nonce", "newAccount": url + "/new-account", "newOrder": url + "/new-order",
			"revokeCert": url + "/revoke", "keyChange": url + "/key-change",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/new-account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "n")
		w.Header().Set("Location", url+"/account/1")
		json.NewEncoder(w).Encode(map[string]string{"status": "valid"})
	})
	mux.HandleFunc("/account/1", func(w http.ResponseWriter, r *http.Request) {
		_, payload := readJWS(t, r)
		w.Header().Set("Replay-Nonce", "n")
		var body struct{ Status string }
		json.Unmarshal(payload, &body)
		f.mu.Lock()
		f.deactivated = body.Status == "deactivated"
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"status": body.Status})
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		header, payload := readJWS(t, r)
		var body struct {
			Certificate string
			Reason      int
		}
		json.Unmarshal(payload, &body)
		der, _ := base64.RawURLEncoding.DecodeString(body.Certificate)
		f.mu.Lock()
		f.revocations = append(f.revocations, fakeRevocation{byKey: header.JSONWebKey, kid: header.KeyID, cert: der, reason: body.Reason})
		f.mu.Unlock()
		w.Header().Set("Replay-Nonce", "n")
		w.WriteHeader(http.StatusOK)
	})

	f.root = filepath.Join(t.TempDir(), "fake-root.crt")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw})
	if err := os.WriteFile(f.root, pemData, 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

// readJWS checks a request's signature with the key it names (its own
// "jwk", or the account's) and returns its header and payload.
func readJWS(t *testing.T, r *http.Request) (jose.Header, []byte) {
	data, _ := io.ReadAll(r.Body)
	jws, err := jose.ParseSigned(string(data), []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.RS256})
	if err != nil {
		t.Errorf("bad JWS: %v", err)
		return jose.Header{}, nil
	}
	header := jws.Signatures[0].Protected
	if header.JSONWebKey != nil {
		if _, err := jws.Verify(header.JSONWebKey); err != nil {
			t.Errorf("signature does not verify with its jwk: %v", err)
		}
	}
	return header, jws.UnsafePayloadWithoutVerification()
}

func (f *fakeACME) conn() connection { return connection{root: f.root, prompt: io.Discard} }

func (f *fakeACME) directory() string { return f.server.URL + "/dir" }

// bxp acme revoke on another ACME CA, signed with the certificate's key or
// with the account key next to it, with the reason given; without either key
// it says to give --key.
func TestACMERevokeOnAnotherCA(t *testing.T) {
	testCA := startTestCA(t) // only to have a certificate and key to revoke
	certFile, keyFile := issueForTest(t, testCA, "web.example.com")
	leaf, err := readLeaf(certFile)
	if err != nil {
		t.Fatal(err)
	}
	fake := startFakeACME(t)

	// Signed with the certificate's own key.
	var out bytes.Buffer
	if err := runACMERevoke(context.Background(), &out, fake.conn(),
		acmeRevokeOptions{cert: certFile, key: keyFile, reason: "key-compromise", directory: fake.directory()}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Revoked") {
		t.Errorf("output:\n%s", out.String())
	}
	// Signed with the account key next to the certificate.
	if err := runACMERevoke(context.Background(), io.Discard, fake.conn(),
		acmeRevokeOptions{cert: certFile, reason: "superseded", directory: fake.directory()}); err != nil {
		t.Fatal(err)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.revocations) != 2 {
		t.Fatalf("%d revocations, want 2", len(fake.revocations))
	}
	byCert, byAccount := fake.revocations[0], fake.revocations[1]
	if byCert.byKey == nil || !sameKey(byCert.byKey.Key, leaf.PublicKey) {
		t.Error("the first request was not signed with the certificate's key")
	}
	if byAccount.byKey != nil || !strings.HasSuffix(byAccount.kid, "/account/1") {
		t.Errorf("the second request was not signed by the account (kid %q)", byAccount.kid)
	}
	if !bytes.Equal(byCert.cert, leaf.Raw) || byCert.reason != 1 || byAccount.reason != 4 {
		t.Errorf("certificate sent: %v; reasons %d and %d, want 1 and 4",
			bytes.Equal(byCert.cert, leaf.Raw), byCert.reason, byAccount.reason)
	}

	// Without the account key and without --key, it says what to give.
	err = runACMERevoke(context.Background(), io.Discard, fake.conn(),
		acmeRevokeOptions{cert: certFile, accountKey: filepath.Join(t.TempDir(), "none.key"), directory: fake.directory()})
	if err == nil || !strings.Contains(err.Error(), "--key") {
		t.Errorf("error = %v", err)
	}
}

// bxp acme deactivate on another ACME CA asks first: after a no the account
// stays, after a yes it is closed.
func TestACMEDeactivateOnAnotherCA(t *testing.T) {
	fake := startFakeACME(t)
	accountKey := filepath.Join(t.TempDir(), accountKeyFile)
	if _, err := loadOrCreateAccountKey(accountKey); err != nil {
		t.Fatal(err)
	}
	account := acmeAccount{accountKey: accountKey, directory: fake.directory()}

	// Answered "no": nothing happens.
	no := func(string) (bool, error) { return false, nil }
	if err := runACMEDeactivate(context.Background(), io.Discard, fake.conn(), account, no); err == nil {
		t.Error("closed without consent")
	}
	fake.mu.Lock()
	closed := fake.deactivated
	fake.mu.Unlock()
	if closed {
		t.Fatal("the account was closed after a no")
	}
	if err := runACMEDeactivate(context.Background(), io.Discard, fake.conn(), account, nil); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if !fake.deactivated {
		t.Error("the account was not closed")
	}
}

// Without a terminal to ask on, closing an account needs --yes.
func TestACMEDeactivateNeedsYes(t *testing.T) {
	cmd := newRootCommand()
	cmd.SetArgs([]string{"acme", "deactivate", "--directory", "https://127.0.0.1:1/dir", "--account-key", filepath.Join(t.TempDir(), "k")})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("error = %v, want one asking for --yes", err)
	}
}
