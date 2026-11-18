// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	acmeclient "golang.org/x/crypto/acme"
)

// fakeTLSHosts plays port 443 of every host, for tls-alpn-01: it answers
// each name with the certificate set for it.
type fakeTLSHosts struct {
	listener net.Listener
	mu       sync.Mutex
	certs    map[string]tls.Certificate
	noALPN   map[string]bool // answer without the acme-tls/1 protocol
}

func newFakeTLSHosts(t testing.TB) *fakeTLSHosts {
	t.Helper()
	h := &fakeTLSHosts{certs: map[string]tls.Certificate{}, noALPN: map[string]bool{}}
	config := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			cert, ok := h.certs[hello.ServerName]
			if !ok {
				return nil, errors.New("no certificate for " + hello.ServerName)
			}
			c := &tls.Config{Certificates: []tls.Certificate{cert}}
			if !h.noALPN[hello.ServerName] {
				c.NextProtos = []string{alpnProtocol}
			}
			return c, nil
		},
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	h.listener = listener
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return h
}

func (h *fakeTLSHosts) set(name string, cert tls.Certificate, alpn bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.certs[name] = cert
	h.noALPN[name] = !alpn
}

// order places an order for names and returns it with its authorizations.
func (e *testEnv) order(client *acmeclient.Client, names ...string) (*acmeclient.Order, []*acmeclient.Authorization) {
	e.t.Helper()
	ctx := context.Background()
	order, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs(names...))
	if err != nil {
		e.t.Fatal(err)
	}
	var authzs []*acmeclient.Authorization
	for _, u := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, u)
		if err != nil {
			e.t.Fatal(err)
		}
		authzs = append(authzs, authz)
	}
	return order, authzs
}

// finish finalizes a ready order and returns the leaf certificate.
func (e *testEnv) finish(client *acmeclient.Client, order *acmeclient.Order, names ...string) *x509.Certificate {
	e.t.Helper()
	ctx := context.Background()
	ready, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		e.t.Fatal(err)
	}
	der, _, err := client.CreateOrderCert(ctx, ready.FinalizeURL, newCSR(e.t, nil, "", names...), false)
	if err != nil {
		e.t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der[0])
	if err != nil {
		e.t.Fatal(err)
	}
	return cert
}

func challengeTypes(authz *acmeclient.Authorization) []string {
	var types []string
	for _, c := range authz.Challenges {
		types = append(types, c.Type)
	}
	return types
}

// A name is offered http-01, dns-01 and tls-alpn-01; a wildcard only dns-01,
// with the base name and the wildcard flag (RFC 8555 7.1.4).
func TestChallengesOffered(t *testing.T) {
	env := newTestEnv(t)
	_, authzs := env.order(env.registered(), "web.example.com", "*.example.com")
	if got := challengeTypes(authzs[0]); !slices.Equal(got, []string{"http-01", "dns-01", "tls-alpn-01"}) {
		t.Errorf("web.example.com: challenges %v", got)
	}
	wild := authzs[1]
	if got := challengeTypes(wild); !slices.Equal(got, []string{"dns-01"}) {
		t.Errorf("*.example.com: challenges %v, want only dns-01", got)
	}
	if !wild.Wildcard || wild.Identifier.Value != "example.com" {
		t.Errorf("wildcard authorization: identifier %q, wildcard %v (RFC 8555 7.1.4)", wild.Identifier.Value, wild.Wildcard)
	}
}

// dns-01: the right TXT record among others proves the name and the
// certificate is issued; nothing is fetched over HTTP; the decided challenge
// shows its status, the others stay pending.
func TestDNS01(t *testing.T) {
	env := newTestEnv(t)
	client := env.registered()
	ctx := context.Background()
	order, authzs := env.order(client, "web.example.com")
	challenge := challengeOfType(t, authzs[0], "dns-01")
	record, err := client.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		t.Fatal(err)
	}
	env.hosts.setTXT("_acme-challenge.web.example.com.", "something else", record)
	if _, err := client.Accept(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WaitAuthorization(ctx, authzs[0].URI); err != nil {
		t.Fatal(err)
	}
	cert := env.finish(client, order, "web.example.com")
	if !slices.Equal(cert.DNSNames, []string{"web.example.com"}) {
		t.Errorf("names %v", cert.DNSNames)
	}
	// Nothing was fetched over HTTP.
	if seen := env.hosts.seen(); len(seen) != 0 {
		t.Errorf("HTTP requests for a dns-01 challenge: %v", seen)
	}
	// The decided challenge shows its status; the others stay pending.
	authz, err := client.GetAuthorization(ctx, authzs[0].URI)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range authz.Challenges {
		want := "pending"
		if c.Type == "dns-01" {
			want = "valid"
		}
		if c.Status != want {
			t.Errorf("%s: status %s, want %s", c.Type, c.Status, want)
		}
	}
}

// A wildcard is proved through the TXT record of the name below it.
func TestWildcardWithDNS01(t *testing.T) {
	env := newTestEnv(t)
	client := env.registered()
	ctx := context.Background()
	order, authzs := env.order(client, "*.example.com")
	challenge := challengeOfType(t, authzs[0], "dns-01")
	record, err := client.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		t.Fatal(err)
	}
	env.hosts.setTXT("_acme-challenge.example.com.", record)
	if _, err := client.Accept(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WaitAuthorization(ctx, authzs[0].URI); err != nil {
		t.Fatal(err)
	}
	cert := env.finish(client, order, "*.example.com")
	if !slices.Equal(cert.DNSNames, []string{"*.example.com"}) {
		t.Errorf("names %v", cert.DNSNames)
	}
}

// http-01 cannot prove a wildcard, even if a client asks for it.
func TestWildcardRefusesHTTP01(t *testing.T) {
	env := newTestEnv(t)
	client := env.registered()
	_, authzs := env.order(client, "*.example.com")
	dns := challengeOfType(t, authzs[0], "dns-01")
	forged := &acmeclient.Challenge{Type: "http-01", URI: strings.Replace(dns.URI, "/dns-01", "/http-01", 1), Token: dns.Token}
	_, err := client.Accept(context.Background(), forged)
	wantProblem(t, err, "malformed")
	if seen := env.hosts.seen(); len(seen) != 0 {
		t.Errorf("HTTP requests for a wildcard: %v", seen)
	}
}

// dns-01 fails with no record, a wrong value, and the key authorization in
// place of its hash.
func TestDNS01Failures(t *testing.T) {
	tests := []struct {
		name    string
		records func(client *acmeclient.Client, token string) []string // nil: no record at all
		want    string
	}{
		{"no record", nil, "dns"},
		{"wrong value", func(*acmeclient.Client, string) []string { return []string{"not it"} }, "incorrectResponse"},
		{"the key authorization itself, not its hash", func(c *acmeclient.Client, token string) []string {
			answer, _ := c.HTTP01ChallengeResponse(token)
			return []string{answer}
		}, "incorrectResponse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			client := env.registered()
			_, authzs := env.order(client, "web.example.com")
			challenge := challengeOfType(t, authzs[0], "dns-01")
			if tt.records != nil {
				env.hosts.setTXT("_acme-challenge.web.example.com.", tt.records(client, challenge.Token)...)
			}
			ctx := context.Background()
			if _, err := client.Accept(ctx, challenge); err != nil {
				t.Fatal(err)
			}
			_, err := client.WaitAuthorization(ctx, authzs[0].URI)
			var authzErr *acmeclient.AuthorizationError
			if !errors.As(err, &authzErr) {
				t.Fatalf("error = %v, want the authorization to fail", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want type %s", err, tt.want)
			}
		})
	}
}

// tls-alpn-01: the right certificate on port 443 with acme-tls/1 proves the
// name and the certificate is issued.
func TestTLSALPN01(t *testing.T) {
	env := newTestEnv(t)
	client := env.registered()
	ctx := context.Background()
	order, authzs := env.order(client, "web.example.com")
	challenge := challengeOfType(t, authzs[0], "tls-alpn-01")
	cert, err := client.TLSALPN01ChallengeCert(challenge.Token, "web.example.com")
	if err != nil {
		t.Fatal(err)
	}
	env.hosts.tls.set("web.example.com", cert, true)
	if _, err := client.Accept(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WaitAuthorization(ctx, authzs[0].URI); err != nil {
		t.Fatal(err)
	}
	env.finish(client, order, "web.example.com")
}

// alpnCert makes a challenge certificate by hand, to break one rule at a
// time.
func alpnCert(t *testing.T, names []string, hash []byte, critical bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	value, err := asn1.Marshal(hash)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "challenge"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		DNSNames:        names,
		ExtraExtensions: []pkix.Extension{{Id: idPeAcmeIdentifier, Critical: critical, Value: value}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tls-alpn-01 fails with nothing on port 443, without acme-tls/1, with
// another account's certificate, with the extension not critical, and with a
// second name in the certificate.
func TestTLSALPN01Failures(t *testing.T) {
	const name = "web.example.com"
	tests := []struct {
		name  string
		setup func(t *testing.T, env *testEnv, client *acmeclient.Client, token string)
		want  string
	}{
		{"nothing on port 443", func(*testing.T, *testEnv, *acmeclient.Client, string) {}, "tls"},
		{"no acme-tls/1", func(t *testing.T, env *testEnv, client *acmeclient.Client, token string) {
			cert, _ := client.TLSALPN01ChallengeCert(token, name)
			env.hosts.tls.set(name, cert, false)
		}, "acme-tls/1"},
		{"another account's certificate", func(t *testing.T, env *testEnv, _ *acmeclient.Client, token string) {
			cert, _ := env.newClient().TLSALPN01ChallengeCert(token, name)
			env.hosts.tls.set(name, cert, true)
		}, "wrong value"},
		{"extension not critical", func(t *testing.T, env *testEnv, client *acmeclient.Client, token string) {
			answer, _ := client.HTTP01ChallengeResponse(token)
			sum := sha256.Sum256([]byte(answer))
			env.hosts.tls.set(name, alpnCert(t, []string{name}, sum[:], false), true)
		}, "critical"},
		{"a second name", func(t *testing.T, env *testEnv, client *acmeclient.Client, token string) {
			answer, _ := client.HTTP01ChallengeResponse(token)
			sum := sha256.Sum256([]byte(answer))
			env.hosts.tls.set(name, alpnCert(t, []string{name, "other.example.com"}, sum[:], true), true)
		}, "nothing else"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			client := env.registered()
			_, authzs := env.order(client, name)
			challenge := challengeOfType(t, authzs[0], "tls-alpn-01")
			tt.setup(t, env, client, challenge.Token)
			ctx := context.Background()
			if _, err := client.Accept(ctx, challenge); err != nil {
				t.Fatal(err)
			}
			_, err := client.WaitAuthorization(ctx, authzs[0].URI)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// Orders are limited per account: over the limit, 429 rateLimited with
// Retry-After; another account is not affected.
func TestOrderLimitPerAccount(t *testing.T) {
	env := newTestEnv(t)
	env.server.ordersPerAccount = newWindowLimiter(2)
	client := env.registered()
	// The client honors Retry-After and would wait an hour; fail at once.
	client.RetryBackoff = noRetry
	ctx := context.Background()
	for range 2 {
		if _, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs("web.example.com")); err != nil {
			t.Fatal(err)
		}
	}
	_, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs("web.example.com"))
	wantProblem(t, err, "rateLimited")
	var acmeErr *acmeclient.Error
	if errors.As(err, &acmeErr) && (acmeErr.StatusCode != http.StatusTooManyRequests || acmeErr.Header.Get("Retry-After") == "") {
		t.Errorf("status %d, Retry-After %q", acmeErr.StatusCode, acmeErr.Header.Get("Retry-After"))
	}
	// Another account is not affected.
	if _, err := env.registered().AuthorizeOrder(ctx, acmeclient.DomainIDs("web.example.com")); err != nil {
		t.Errorf("another account: %v", err)
	}
}

// New accounts are limited per address; an existing account is still found.
func TestAccountLimitPerAddress(t *testing.T) {
	env := newTestEnv(t)
	env.server.accountsPerIP = newWindowLimiter(1)
	first := env.registered()
	second := env.newClient()
	second.RetryBackoff = noRetry
	_, err := second.Register(context.Background(), &acmeclient.Account{}, acmeclient.AcceptTOS)
	wantProblem(t, err, "rateLimited")
	// An existing account is found again, limit or not.
	if _, err := first.GetReg(context.Background(), ""); err != nil {
		t.Errorf("existing account: %v", err)
	}
}

// The rate limiter is full after its limit for that key only, says when to
// retry, and empties after its window.
func TestWindowLimiter(t *testing.T) {
	now := time.Now()
	l := newWindowLimiter(2)
	l.now = func() time.Time { return now }
	l.add("a")
	l.add("a")
	if full, retry := l.full("a"); !full || retry <= 0 || retry > limitWindow {
		t.Errorf("full %v, retry %v", full, retry)
	}
	if full, _ := l.full("b"); full {
		t.Error("another key is full")
	}
	now = now.Add(limitWindow + time.Second)
	if full, _ := l.full("a"); full {
		t.Error("still full after the window")
	}
}

func noRetry(int, *http.Request, *http.Response) time.Duration { return -1 }

// Limits change while the server runs (configuration reload), and 0 means
// no limit.
func TestSetLimits(t *testing.T) {
	env := newTestEnv(t)
	env.server.SetLimits(Limits{AccountsPerIP: 0, OrdersPerAccount: 1})
	client := env.registered()
	client.RetryBackoff = noRetry
	ctx := context.Background()
	if _, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs("web.example.com")); err != nil {
		t.Fatal(err)
	}
	_, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs("web.example.com"))
	wantProblem(t, err, "rateLimited")

	env.server.SetLimits(Limits{AccountsPerIP: 0, OrdersPerAccount: 0})
	for range 5 {
		if _, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs("web.example.com")); err != nil {
			t.Fatalf("with no limit: %v", err)
		}
	}
	for range 5 {
		env.registered() // accounts: no limit either
	}
}

// The administrator chooses the challenge types.
func TestChosenChallenges(t *testing.T) {
	env := newTestEnv(t)
	env.server.SetChallenges([]string{"tls-alpn-01", "dns-01"})
	client := env.registered()
	_, authzs := env.order(client, "web.example.com")
	// In the server's order, not the configuration's.
	if got := challengeTypes(authzs[0]); !slices.Equal(got, []string{"dns-01", "tls-alpn-01"}) {
		t.Errorf("challenges %v", got)
	}
	// A type that is not offered cannot be used by its address either.
	dns := challengeOfType(t, authzs[0], "dns-01")
	forged := &acmeclient.Challenge{Type: "http-01", URI: strings.Replace(dns.URI, "/dns-01", "/http-01", 1), Token: dns.Token}
	_, err := client.Accept(context.Background(), forged)
	wantProblem(t, err, "malformed")
	if seen := env.hosts.seen(); len(seen) != 0 {
		t.Errorf("HTTP requests although http-01 is off: %v", seen)
	}
}

// Without dns-01, a wildcard is refused at the order.
func TestWildcardWithoutDNS01(t *testing.T) {
	env := newTestEnv(t)
	env.server.SetChallenges([]string{"http-01", "tls-alpn-01"})
	_, err := env.registered().AuthorizeOrder(context.Background(), acmeclient.DomainIDs("*.example.com"))
	wantProblem(t, err, "rejectedIdentifier")
	if err == nil || !strings.Contains(err.Error(), "dns-01") {
		t.Errorf("error = %v, want it to name dns-01", err)
	}
}

// A reload that takes a type away applies to pending authorizations too.
func TestChallengesChangeForPendingAuthorizations(t *testing.T) {
	env := newTestEnv(t)
	client := env.registered()
	_, authzs := env.order(client, "web.example.com")
	challenge := http01Challenge(t, authzs[0])
	env.server.SetChallenges([]string{"dns-01"})
	_, err := client.Accept(context.Background(), challenge)
	wantProblem(t, err, "malformed")
	// Empty means all again.
	env.server.SetChallenges(nil)
	authz, err := client.GetAuthorization(context.Background(), authzs[0].URI)
	if err != nil {
		t.Fatal(err)
	}
	if got := challengeTypes(authz); len(got) != 3 {
		t.Errorf("challenges %v, want all three", got)
	}
}

// Key change (RFC 8555, section 7.3.5), with the client's own rollover:
// afterwards the account works with the new key only.
func TestKeyChange(t *testing.T) {
	env := newTestEnv(t)
	client := env.registered()
	ctx := context.Background()
	account, err := client.GetReg(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	oldKey := client.Key
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := client.AccountKeyRollover(ctx, newKey); err != nil {
		t.Fatal(err)
	}
	// The client now signs with the new key, for the same account.
	again, err := client.GetReg(ctx, "")
	if err != nil || again.URI != account.URI {
		t.Fatalf("after the change: %+v, %v", again, err)
	}
	if _, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs("web.example.com")); err != nil {
		t.Errorf("order with the new key: %v", err)
	}
	// The old key no longer finds it.
	old := &acmeclient.Client{Key: oldKey, DirectoryURL: client.DirectoryURL, HTTPClient: env.http}
	if _, err := old.GetReg(ctx, ""); err == nil {
		t.Error("the old key still finds the account")
	}
	// Another account's key cannot be taken over.
	other := env.registered()
	err = client.AccountKeyRollover(ctx, other.Key)
	var acmeErr *acmeclient.Error
	if !errors.As(err, &acmeErr) || acmeErr.StatusCode != http.StatusConflict {
		t.Errorf("rollover to another account's key: %v, want 409", err)
	}
}
