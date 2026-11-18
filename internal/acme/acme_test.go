// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v4"
	acmeclient "golang.org/x/crypto/acme"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/policy"
	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// testEnv is an ACME server with a CA behind it, and a stand-in for the
// hosts whose names are being proved.
type testEnv struct {
	t      testing.TB
	ca     *ca.CA
	server *Server
	url    string       // where the ACME server listens, https://127.0.0.1:<port>
	http   *http.Client // trusts the test server's certificate
	hosts  *fakeHosts
}

// fakeHosts plays port 80 of every host. The ACME server's challenge
// requests all end up here, whatever name they are for.
type fakeHosts struct {
	server *httptest.Server

	mu       sync.Mutex
	files    map[string]string   // "host/path" -> content
	requests []string            // "host/path" of every request seen
	redirect string              // if set, answer everything with a redirect to it
	txt      map[string][]string // DNS name -> TXT records
	lookups  []string            // DNS names looked up
	tls      *fakeTLSHosts
}

// setTXT sets the TXT records of a DNS name.
func (h *fakeHosts) setTXT(name string, values ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.txt == nil {
		h.txt = make(map[string][]string)
	}
	h.txt[name] = values
}

func (h *fakeHosts) lookupTXT(_ context.Context, name string) ([]string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lookups = append(h.lookups, name)
	values, ok := h.txt[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return values, nil
}

func (h *fakeHosts) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := r.Host + r.URL.Path
	h.requests = append(h.requests, key)
	if h.redirect != "" {
		http.Redirect(w, r, h.redirect, http.StatusFound)
		return
	}
	content, ok := h.files[key]
	if !ok {
		http.NotFound(w, r)
		return
	}
	io.WriteString(w, content)
}

// serve makes host answer at path with content.
func (h *fakeHosts) serve(host, path, content string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.files[host+path] = content
}

func (h *fakeHosts) seen() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.requests...)
}

func newTestEnv(t testing.TB) *testEnv {
	t.Helper()
	dir := t.TempDir()
	if err := ca.Init(dir, ca.InitOptions{Name: "Test", Organization: "Test Org", KeyType: ca.KeyTypeECDSA}); err != nil {
		t.Fatal(err)
	}
	authority, err := ca.Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(dir, store.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	authority.Record(db) // as "bxp serve" does: revocation needs the list

	hosts := &fakeHosts{files: make(map[string]string)}
	hosts.server = httptest.NewServer(hosts)
	t.Cleanup(hosts.server.Close)

	server := New(Options{
		CA:    authority,
		Store: db,
		Rules: policy.NewACME([]string{"example.com"}),
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	// Send every challenge request to the fake hosts. The request still
	// carries the real host name, so the fake can tell them apart.
	// Port 443 (tls-alpn-01) goes to the fake TLS hosts, port 80 to the
	// fake web hosts. TXT records (dns-01) come from the fake too.
	tlsHosts := newFakeTLSHosts(t)
	server.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		switch {
		case strings.HasSuffix(address, ":443"):
			return (&net.Dialer{}).DialContext(ctx, network, tlsHosts.listener.Addr().String())
		case strings.HasSuffix(address, ":80"):
			return (&net.Dialer{}).DialContext(ctx, network, hosts.server.Listener.Addr().String())
		default:
			t.Errorf("challenge request to %s, want port 80 or 443", address)
			return nil, errors.New("unexpected port")
		}
	}
	server.lookupTXT = hosts.lookupTXT
	hosts.tls = tlsHosts

	ts := httptest.NewTLSServer(server.Handler())
	t.Cleanup(ts.Close)
	return &testEnv{t: t, ca: authority, server: server, url: ts.URL, http: ts.Client(), hosts: hosts}
}

// newClient returns an ACME client with a new account key. It is the
// client from golang.org/x/crypto: written by other people, against the
// RFC and not against this server.
func (e *testEnv) newClient() *acmeclient.Client {
	e.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		e.t.Fatal(err)
	}
	return &acmeclient.Client{Key: key, DirectoryURL: e.url + DirectoryPath, HTTPClient: e.http}
}

// registered returns a client whose account exists.
func (e *testEnv) registered() *acmeclient.Client {
	e.t.Helper()
	client := e.newClient()
	if _, err := client.Register(context.Background(), &acmeclient.Account{}, acmeclient.AcceptTOS); err != nil {
		e.t.Fatal(err)
	}
	return client
}

// prove answers the challenges of an order, like a client that controls
// the hosts, and waits until the order is ready.
func (e *testEnv) prove(client *acmeclient.Client, order *acmeclient.Order) *acmeclient.Order {
	e.t.Helper()
	ctx := context.Background()
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			e.t.Fatal(err)
		}
		challenge := http01Challenge(e.t, authz)
		answer, err := client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			e.t.Fatal(err)
		}
		e.hosts.serve(authz.Identifier.Value, client.HTTP01ChallengePath(challenge.Token), answer)
		if _, err := client.Accept(ctx, challenge); err != nil {
			e.t.Fatal(err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			e.t.Fatalf("authorization for %s: %v", authz.Identifier.Value, err)
		}
	}
	ready, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		e.t.Fatal(err)
	}
	return ready
}

func http01Challenge(t testing.TB, authz *acmeclient.Authorization) *acmeclient.Challenge {
	t.Helper()
	return challengeOfType(t, authz, "http-01")
}

func challengeOfType(t testing.TB, authz *acmeclient.Authorization, kind string) *acmeclient.Challenge {
	t.Helper()
	for _, c := range authz.Challenges {
		if c.Type == kind {
			return c
		}
	}
	var types []string
	for _, c := range authz.Challenges {
		types = append(types, c.Type)
	}
	t.Fatalf("no %s challenge among %v", kind, types)
	return nil
}

// newCSR returns a CSR in DER form for the given DNS names.
func newCSR(t testing.TB, key crypto.Signer, commonName string, dnsNames ...string) []byte {
	t.Helper()
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}, DNSNames: dnsNames}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// wantProblem checks that err is an ACME error of the given kind.
func wantProblem(t *testing.T, err error, kind string) {
	t.Helper()
	var acmeErr *acmeclient.Error
	if !errors.As(err, &acmeErr) {
		t.Fatalf("error = %v, want an ACME error of type %s", err, kind)
	}
	if want := "urn:ietf:params:acme:error:" + kind; acmeErr.ProblemType != want {
		t.Errorf("error type = %s, want %s (detail: %s)", acmeErr.ProblemType, want, acmeErr.Detail)
	}
}

// The whole road, driven by an independent ACME client.
func TestIssueCertificate(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	client := env.registered()

	order, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs("web.example.com", "API.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if order.Status != acmeclient.StatusPending || len(order.AuthzURLs) != 2 {
		t.Fatalf("new order: status %s with %d authorizations, want pending with 2", order.Status, len(order.AuthzURLs))
	}

	order = env.prove(client, order)
	if order.Status != acmeclient.StatusReady {
		t.Fatalf("order status = %s, want ready", order.Status)
	}

	chain, certURL, err := client.CreateOrderCert(ctx, order.FinalizeURL, newCSR(t, nil, "web.example.com", "web.example.com", "api.example.com"), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 {
		t.Fatalf("the chain has %d certificates, want 2 (leaf and intermediate)", len(chain))
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(chain[1])
	if err != nil {
		t.Fatal(err)
	}

	// A TLS client that trusts only the root must accept it for both names.
	roots := x509.NewCertPool()
	roots.AddCert(env.ca.RootCert())
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	for _, host := range []string{"web.example.com", "api.example.com"} {
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: intermediates, DNSName: host,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			t.Errorf("certificate does not verify for %s: %v", host, err)
		}
	}
	if len(leaf.DNSNames) != 2 {
		t.Errorf("DNS names = %v, want the two of the order", leaf.DNSNames)
	}

	// The challenge requests went to the right hosts and paths.
	seen := strings.Join(env.hosts.seen(), " ")
	for _, host := range []string{"web.example.com", "api.example.com"} {
		if !strings.Contains(seen, host+"/.well-known/acme-challenge/") {
			t.Errorf("no challenge request for %s among: %s", host, seen)
		}
	}

	// The certificate can be downloaded again, and the order says valid.
	again, err := client.FetchCert(ctx, certURL, true)
	if err != nil || len(again) != 2 || !bytes.Equal(again[0], chain[0]) {
		t.Errorf("second download: %d certificates, error %v", len(again), err)
	}
	final, err := client.GetOrder(ctx, order.URI)
	if err != nil || final.Status != acmeclient.StatusValid {
		t.Errorf("order after issuance: %+v, %v; want valid", final, err)
	}
}

// ACME accounts: a key without an account is told so; registering creates a
// valid account; the same key cannot register twice; a client with only the
// key finds its account again, with its contact.
func TestAccounts(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	client := env.newClient()

	// Before registering, the key has no account.
	if _, err := client.GetReg(ctx, ""); !errors.Is(err, acmeclient.ErrNoAccount) {
		t.Errorf("unknown key: error = %v, want ErrNoAccount", err)
	}

	account, err := client.Register(ctx, &acmeclient.Account{Contact: []string{"mailto:admin@example.com"}}, acmeclient.AcceptTOS)
	if err != nil {
		t.Fatal(err)
	}
	if account.Status != acmeclient.StatusValid || !strings.HasPrefix(account.URI, env.url+"/acme/acct/") {
		t.Errorf("account = %+v", account)
	}

	// The same key again: no second account.
	if _, err := client.Register(ctx, &acmeclient.Account{}, acmeclient.AcceptTOS); !errors.Is(err, acmeclient.ErrAccountAlreadyExists) {
		t.Errorf("second registration: error = %v, want ErrAccountAlreadyExists", err)
	}

	// A client that only has its key finds its account again.
	sameKey := &acmeclient.Client{Key: client.Key, DirectoryURL: client.DirectoryURL, HTTPClient: env.http}
	found, err := sameKey.GetReg(ctx, "")
	if err != nil || found.URI != account.URI {
		t.Errorf("found %+v, %v; want the account %s", found, err, account.URI)
	}
	if len(found.Contact) != 1 || found.Contact[0] != "mailto:admin@example.com" {
		t.Errorf("contact = %v", found.Contact)
	}
}

// An order is refused for names outside the allowed domains (another domain,
// a look-alike, one bad name among good ones, a wildcard elsewhere, an
// invalid host name), for an IP address outside the configured ranges, and
// with no names; no host is contacted for a refused order.
func TestOrderRefusesNamesTheCAMayNotIssue(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	client := env.registered()

	refused := map[string][]string{
		"other domain":         {"www.other.com"},
		"look-alike domain":    {"badexample.com"},
		"one good and one bad": {"web.example.com", "www.other.com"},
		"wildcard elsewhere":   {"*.other.com"},
		"not a host name":      {"web_1.example.com"},
	}
	for name, domains := range refused {
		t.Run(name, func(t *testing.T) {
			_, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs(domains...))
			wantProblem(t, err, "rejectedIdentifier")
		})
	}

	// IP addresses: only in configured ranges, and there are none here.
	_, err := client.AuthorizeOrder(ctx, acmeclient.IPIDs("10.0.0.5"))
	wantProblem(t, err, "rejectedIdentifier")

	_, err = client.AuthorizeOrder(ctx, nil)
	wantProblem(t, err, "malformed")

	// None of these may have caused a request to any host.
	if seen := env.hosts.seen(); len(seen) != 0 {
		t.Errorf("challenge requests were made for refused orders: %v", seen)
	}
}

// A client that cannot put the right answer on the host gets nothing.
func TestChallengeFailures(t *testing.T) {
	tests := map[string]func(env *testEnv, client *acmeclient.Client, authz *acmeclient.Authorization, challenge *acmeclient.Challenge){
		"nothing at the address": func(env *testEnv, client *acmeclient.Client, authz *acmeclient.Authorization, challenge *acmeclient.Challenge) {
		},
		"wrong text": func(env *testEnv, client *acmeclient.Client, authz *acmeclient.Authorization, challenge *acmeclient.Challenge) {
			env.hosts.serve(authz.Identifier.Value, client.HTTP01ChallengePath(challenge.Token), "something else")
		},
		"the token alone": func(env *testEnv, client *acmeclient.Client, authz *acmeclient.Authorization, challenge *acmeclient.Challenge) {
			env.hosts.serve(authz.Identifier.Value, client.HTTP01ChallengePath(challenge.Token), challenge.Token)
		},
		"answer of another account": func(env *testEnv, client *acmeclient.Client, authz *acmeclient.Authorization, challenge *acmeclient.Challenge) {
			// Someone else controls the host and answers with their
			// own key. That must not help this account.
			other := env.newClient()
			answer, _ := other.HTTP01ChallengeResponse(challenge.Token)
			env.hosts.serve(authz.Identifier.Value, client.HTTP01ChallengePath(challenge.Token), answer)
		},
		"right text on another host": func(env *testEnv, client *acmeclient.Client, authz *acmeclient.Authorization, challenge *acmeclient.Challenge) {
			answer, _ := client.HTTP01ChallengeResponse(challenge.Token)
			env.hosts.serve("other.example.com", client.HTTP01ChallengePath(challenge.Token), answer)
		},
		"a redirect": func(env *testEnv, client *acmeclient.Client, authz *acmeclient.Authorization, challenge *acmeclient.Challenge) {
			// The redirect points at a place that has the right
			// answer. The server must not go there.
			answer, _ := client.HTTP01ChallengeResponse(challenge.Token)
			env.hosts.serve("elsewhere.example.com", "/answer", answer)
			env.hosts.mu.Lock()
			env.hosts.redirect = "http://elsewhere.example.com/answer"
			env.hosts.mu.Unlock()
		},
	}
	for name, setUp := range tests {
		t.Run(name, func(t *testing.T) {
			env := newTestEnv(t)
			ctx := context.Background()
			client := env.registered()

			order, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs("web.example.com"))
			if err != nil {
				t.Fatal(err)
			}
			authz, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
			if err != nil {
				t.Fatal(err)
			}
			challenge := http01Challenge(t, authz)
			setUp(env, client, authz, challenge)

			if _, err := client.Accept(ctx, challenge); err != nil {
				t.Fatal(err)
			}
			_, err = client.WaitAuthorization(ctx, order.AuthzURLs[0])
			var authzErr *acmeclient.AuthorizationError
			if !errors.As(err, &authzErr) {
				t.Fatalf("authorization: error = %v, want it to be refused", err)
			}

			// The order is lost, and no certificate can be had from it.
			_, _, err = client.CreateOrderCert(ctx, order.FinalizeURL, newCSR(t, nil, "", "web.example.com"), true)
			if err == nil {
				t.Fatal("a certificate was issued although the challenge failed")
			}

			// A failed proof stays failed, even if the right answer
			// shows up later: the client has to place a new order.
			env.hosts.mu.Lock()
			env.hosts.redirect = ""
			env.hosts.mu.Unlock()
			answer, _ := client.HTTP01ChallengeResponse(challenge.Token)
			env.hosts.serve("web.example.com", client.HTTP01ChallengePath(challenge.Token), answer)
			client.Accept(ctx, challenge)
			again, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
			if err != nil || again.Status != acmeclient.StatusInvalid {
				t.Errorf("after a late right answer: status %v, error %v; want invalid", again.Status, err)
			}
		})
	}
}

// An order cannot be finalized before its names are proved.
func TestFinalizeBeforeTheNamesAreProved(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	client := env.registered()

	order, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs("web.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = client.CreateOrderCert(ctx, order.FinalizeURL, newCSR(t, nil, "", "web.example.com"), true)
	wantProblem(t, err, "orderNotReady")
}

// The certificate may contain exactly the proved names, nothing more.
func TestFinalizeRefusesCSRsThatDoNotFitTheOrder(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	client := env.registered()

	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	withIP, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{"web.example.com"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.5")},
	}, mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	withEmail, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{"web.example.com"}, EmailAddresses: []string{"root@example.com"},
	}, mustKey(t))
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string][]byte{
		"an extra name":            newCSR(t, nil, "", "web.example.com", "db.example.com"),
		"an extra name outside":    newCSR(t, nil, "", "web.example.com", "www.other.com"),
		"another name":             newCSR(t, nil, "", "db.example.com"),
		"extra common name":        newCSR(t, nil, "db.example.com", "web.example.com"),
		"name only as common name": newCSR(t, nil, "web.example.com"),
		"no names":                 newCSR(t, nil, ""),
		"an IP address as well":    withIP,
		"an email address as well": withEmail,
		"the account key":          newCSR(t, client.Key, "", "web.example.com"),
		"a weak key":               newCSR(t, weakKey, "", "web.example.com"),
		"not a CSR":                []byte("hello"),
	}
	for name, csr := range tests {
		t.Run(name, func(t *testing.T) {
			order, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs("web.example.com"))
			if err != nil {
				t.Fatal(err)
			}
			order = env.prove(client, order)

			_, _, err = client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
			wantProblem(t, err, "badCSR")

			// The refusal did not spoil the order: a fitting CSR works.
			if _, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, newCSR(t, nil, "", "web.example.com"), true); err != nil {
				t.Errorf("fitting CSR after the refusal: %v", err)
			}
		})
	}
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// One account must not see or use what belongs to another.
func TestAccountsAreKeptApart(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	alice := env.registered()
	mallory := env.registered()

	order, err := alice.AuthorizeOrder(ctx, acmeclient.DomainIDs("web.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	order = env.prove(alice, order)

	// Mallory tries everything with the addresses of Alice's order.
	if _, err := mallory.GetOrder(ctx, order.URI); err == nil {
		t.Error("another account can read the order")
	}
	if _, err := mallory.GetAuthorization(ctx, order.AuthzURLs[0]); err == nil {
		t.Error("another account can read the authorization")
	}
	// Alice proved the name. Mallory must not get the certificate for it.
	if _, _, err := mallory.CreateOrderCert(ctx, order.FinalizeURL, newCSR(t, nil, "", "web.example.com"), true); err == nil {
		t.Fatal("another account got a certificate from the order")
	}

	chain, certURL, err := alice.CreateOrderCert(ctx, order.FinalizeURL, newCSR(t, nil, "", "web.example.com"), true)
	if err != nil || len(chain) == 0 {
		t.Fatal(err)
	}
	if _, err := mallory.FetchCert(ctx, certURL, true); err == nil {
		t.Error("another account can download the certificate")
	}

	// And an account address is only for its own account.
	aliceAccount, _ := alice.GetReg(ctx, "")
	status, kind := env.rawPost(mallory, aliceAccount.URI, "")
	if status != http.StatusForbidden || kind != "unauthorized" {
		t.Errorf("reading another account: status %d, type %s; want 403 unauthorized", status, kind)
	}
}

// ---- Hand-built requests, for what an honest client never sends ----

// rawRequest describes one signed request, with the parts a test may
// want to get wrong.
type rawRequest struct {
	key       crypto.Signer
	kid       string // the account address; empty: send the public key instead
	nonce     string
	signedURL string // the "url" header
	sendTo    string // where the request really goes
	payload   string
	alg       jose.SignatureAlgorithm
}

type staticNonce string

func (n staticNonce) Nonce() (string, error) { return string(n), nil }

// sign builds the JWS body of a request.
func (e *testEnv) sign(req rawRequest) []byte {
	e.t.Helper()
	if req.alg == "" {
		req.alg = jose.ES256
	}
	opts := &jose.SignerOptions{NonceSource: staticNonce(req.nonce)}
	opts = opts.WithHeader("url", req.signedURL)
	var signingKey any = req.key
	if req.kid != "" {
		signingKey = jose.JSONWebKey{Key: req.key, KeyID: req.kid}
	} else {
		opts.EmbedJWK = true
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: req.alg, Key: signingKey}, opts)
	if err != nil {
		e.t.Fatal(err)
	}
	jws, err := signer.Sign([]byte(req.payload))
	if err != nil {
		e.t.Fatal(err)
	}
	return []byte(jws.FullSerialize())
}

// send posts a body and returns the status and the kind of ACME error.
func (e *testEnv) send(address string, body []byte) (status int, kind string) {
	e.t.Helper()
	resp, err := e.http.Post(address, "application/jose+json", bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Replay-Nonce") == "" {
		e.t.Errorf("%s: the answer (status %d) carries no new nonce", address, resp.StatusCode)
	}
	var p problem
	json.NewDecoder(resp.Body).Decode(&p)
	return resp.StatusCode, strings.TrimPrefix(p.Type, "urn:ietf:params:acme:error:")
}

// nonce fetches a fresh nonce.
func (e *testEnv) nonce() string {
	e.t.Helper()
	resp, err := e.http.Head(e.url + "/acme/new-nonce")
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		e.t.Fatal("no nonce")
	}
	return nonce
}

// rawPost sends a correct request for a registered client.
func (e *testEnv) rawPost(client *acmeclient.Client, address, payload string) (int, string) {
	e.t.Helper()
	account, err := client.GetReg(context.Background(), "")
	if err != nil {
		e.t.Fatal(err)
	}
	return e.send(address, e.sign(rawRequest{
		key: client.Key, kid: account.URI, nonce: e.nonce(), signedURL: address, payload: payload,
	}))
}

// Every signed ACME request is checked: a nonce works once and must be real;
// the signed URL must be this endpoint of this server; the signature must be
// the account's key, over the content sent; the account must exist and be
// this server's; only new-account may carry a key; shared-secret and
// unsigned requests, and requests that are too large, are refused.
func TestSignedRequestChecks(t *testing.T) {
	env := newTestEnv(t)
	client := env.registered()
	account, err := client.GetReg(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	newOrder := env.url + "/acme/new-order"
	payload := `{"identifiers":[{"type":"dns","value":"web.example.com"}]}`
	good := func() rawRequest {
		return rawRequest{key: client.Key, kid: account.URI, nonce: env.nonce(), signedURL: newOrder, payload: payload}
	}

	// First show that the hand-built request is right, so that the
	// failures below are caused by what each test changes.
	if status, kind := env.send(newOrder, env.sign(good())); status != http.StatusCreated {
		t.Fatalf("a correct request: status %d, error %s; want 201", status, kind)
	}

	t.Run("a nonce works only once", func(t *testing.T) {
		body := env.sign(good())
		if status, _ := env.send(newOrder, body); status != http.StatusCreated {
			t.Fatalf("first use: status %d, want 201", status)
		}
		// The very same request again: a recorded request, replayed.
		if status, kind := env.send(newOrder, body); status != http.StatusBadRequest || kind != "badNonce" {
			t.Errorf("replay: status %d, type %s; want 400 badNonce", status, kind)
		}
	})

	t.Run("a made-up nonce", func(t *testing.T) {
		req := good()
		req.nonce = "made-up-nonce"
		if status, kind := env.send(newOrder, env.sign(req)); status != http.StatusBadRequest || kind != "badNonce" {
			t.Errorf("status %d, type %s; want 400 badNonce", status, kind)
		}
	})

	t.Run("signed for another address", func(t *testing.T) {
		// A request the client signed for one endpoint, sent to another.
		req := good()
		req.signedURL = env.url + "/acme/new-account"
		if status, kind := env.send(newOrder, env.sign(req)); status != http.StatusUnauthorized || kind != "unauthorized" {
			t.Errorf("status %d, type %s; want 401 unauthorized", status, kind)
		}
	})

	t.Run("signed for another server", func(t *testing.T) {
		req := good()
		req.signedURL = "https://other-ca.example.com/acme/new-order"
		if status, kind := env.send(newOrder, env.sign(req)); status != http.StatusUnauthorized || kind != "unauthorized" {
			t.Errorf("status %d, type %s; want 401 unauthorized", status, kind)
		}
	})

	t.Run("signed with another key", func(t *testing.T) {
		// Alice's account address, but not Alice's key.
		req := good()
		req.key = mustKey(t)
		if status, kind := env.send(newOrder, env.sign(req)); status != http.StatusUnauthorized || kind != "unauthorized" {
			t.Errorf("status %d, type %s; want 401 unauthorized", status, kind)
		}
	})

	t.Run("content changed after signing", func(t *testing.T) {
		var jws map[string]string
		if err := json.Unmarshal(env.sign(good()), &jws); err != nil {
			t.Fatal(err)
		}
		other := env.sign(rawRequest{key: mustKey(t), kid: account.URI, nonce: "x", signedURL: newOrder,
			payload: `{"identifiers":[{"type":"dns","value":"db.example.com"}]}`})
		var otherJWS map[string]string
		json.Unmarshal(other, &otherJWS)
		jws["payload"] = otherJWS["payload"]
		body, _ := json.Marshal(jws)
		if status, kind := env.send(newOrder, body); status != http.StatusUnauthorized || kind != "unauthorized" {
			t.Errorf("status %d, type %s; want 401 unauthorized", status, kind)
		}
	})

	t.Run("unknown account", func(t *testing.T) {
		req := good()
		req.kid = env.url + "/acme/acct/does-not-exist"
		if status, kind := env.send(newOrder, env.sign(req)); status != http.StatusBadRequest || kind != "accountDoesNotExist" {
			t.Errorf("status %d, type %s; want 400 accountDoesNotExist", status, kind)
		}
	})

	t.Run("account address of another server", func(t *testing.T) {
		req := good()
		req.kid = "https://other-ca.example.com/acme/acct/" + strings.TrimPrefix(account.URI, env.url+"/acme/acct/")
		if status, kind := env.send(newOrder, env.sign(req)); status != http.StatusBadRequest || kind != "accountDoesNotExist" {
			t.Errorf("status %d, type %s; want 400 accountDoesNotExist", status, kind)
		}
	})

	t.Run("a key in place of the account", func(t *testing.T) {
		// Anybody can make a key. Only new-account may take one.
		req := good()
		req.kid = ""
		if status, kind := env.send(newOrder, env.sign(req)); status != http.StatusBadRequest || kind != "malformed" {
			t.Errorf("status %d, type %s; want 400 malformed", status, kind)
		}
	})

	t.Run("signed with a shared secret", func(t *testing.T) {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")},
			(&jose.SignerOptions{NonceSource: staticNonce(env.nonce())}).WithHeader("url", newOrder).WithHeader("kid", account.URI))
		if err != nil {
			t.Fatal(err)
		}
		jws, _ := signer.Sign([]byte(payload))
		if status, kind := env.send(newOrder, []byte(jws.FullSerialize())); status != http.StatusBadRequest || kind != "badSignatureAlgorithm" {
			t.Errorf("status %d, type %s; want 400 badSignatureAlgorithm", status, kind)
		}
	})

	t.Run("not signed at all", func(t *testing.T) {
		for _, body := range []string{"", "hello", "{}", payload,
			// Algorithm "none": a JWS that claims to need no signature.
			`{"protected":"eyJhbGciOiJub25lIn0","payload":"e30","signature":""}`} {
			if status, _ := env.send(newOrder, []byte(body)); status != http.StatusBadRequest {
				t.Errorf("body %q: status %d, want 400", body, status)
			}
		}
	})

	t.Run("too large", func(t *testing.T) {
		body := bytes.Repeat([]byte("a"), maxBodyBytes+1)
		if status, _ := env.send(newOrder, body); status != http.StatusBadRequest {
			t.Errorf("status %d, want 400", status)
		}
	})
}

// new-account must carry a key, not an account address; asking only for an
// existing account with an unknown key says it does not exist, and creates
// none.
func TestNewAccountChecks(t *testing.T) {
	env := newTestEnv(t)
	client := env.registered()
	account, _ := client.GetReg(context.Background(), "")
	newAccount := env.url + "/acme/new-account"

	// new-account must carry the key itself, not an account address.
	status, kind := env.send(newAccount, env.sign(rawRequest{
		key: client.Key, kid: account.URI, nonce: env.nonce(), signedURL: newAccount, payload: `{"termsOfServiceAgreed":true}`,
	}))
	if status != http.StatusBadRequest || kind != "malformed" {
		t.Errorf("new-account with a kid: status %d, type %s; want 400 malformed", status, kind)
	}

	// Asking for an account that does not exist creates none.
	stranger := mustKey(t)
	status, kind = env.send(newAccount, env.sign(rawRequest{
		key: stranger, nonce: env.nonce(), signedURL: newAccount, payload: `{"onlyReturnExisting":true}`,
	}))
	if status != http.StatusBadRequest || kind != "accountDoesNotExist" {
		t.Errorf("onlyReturnExisting for an unknown key: status %d, type %s; want 400 accountDoesNotExist", status, kind)
	}
	status, kind = env.send(newAccount, env.sign(rawRequest{
		key: stranger, nonce: env.nonce(), signedURL: newAccount, payload: `{"onlyReturnExisting":true}`,
	}))
	if status != http.StatusBadRequest || kind != "accountDoesNotExist" {
		t.Errorf("the question created an account: status %d, type %s", status, kind)
	}
}

// Changing an account's contacts or deactivating it is refused as
// unsupported, and the account stays as it was.
func TestChangingContactsIsRefused(t *testing.T) {
	env := newTestEnv(t)
	client := env.registered()
	account, _ := client.GetReg(context.Background(), "")

	// Changing contacts is not supported. The server must say so, and
	// not answer as if it had been done.
	for _, payload := range []string{`{"contact":["mailto:new@example.com"]}`, `{"status":"revoked"}`} {
		status, kind := env.rawPost(client, account.URI, payload)
		if status != http.StatusBadRequest || kind != "malformed" {
			t.Errorf("%s: status %d, type %s; want 400 malformed", payload, status, kind)
		}
	}
	if got, err := client.GetReg(context.Background(), ""); err != nil || got.Status != "valid" {
		t.Errorf("the account changed: %+v, %v", got, err)
	}
}

// The directory lists every endpoint, renewal information included, and
// every nonce is different.
func TestDirectoryAndNonce(t *testing.T) {
	env := newTestEnv(t)

	resp, err := env.http.Get(env.url + DirectoryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var dir directoryJSON
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		t.Fatal(err)
	}
	want := directoryJSON{
		NewNonce:    env.url + "/acme/new-nonce",
		NewAccount:  env.url + "/acme/new-account",
		NewOrder:    env.url + "/acme/new-order",
		KeyChange:   env.url + "/acme/key-change",
		RevokeCert:  env.url + "/acme/revoke-cert",
		RenewalInfo: env.url + "/acme/renewal-info",
	}
	if dir != want {
		t.Errorf("directory = %+v, want %+v", dir, want)
	}

	// Every nonce is different.
	if a, b := env.nonce(), env.nonce(); a == b {
		t.Errorf("two nonces are the same: %s", a)
	}
}

// With a public URL set, the directory's addresses start with it.
func TestPublicURLIsUsedWhenSet(t *testing.T) {
	env := newTestEnv(t)
	env.server.publicURL = "https://ca.example.com:8443"

	resp, err := env.http.Get(env.url + DirectoryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var dir directoryJSON
	json.NewDecoder(resp.Body).Decode(&dir)
	if dir.NewOrder != "https://ca.example.com:8443/acme/new-order" {
		t.Errorf("newOrder = %s, want it to start with the public URL", dir.NewOrder)
	}
}

// A nonce works once, an unknown nonce never; nonces collected without being
// used cannot grow the server's memory beyond a limit.
func TestNoncesAreForgottenWhenUsedOrTooMany(t *testing.T) {
	env := newTestEnv(t)
	s := env.server

	nonce, err := s.newNonce()
	if err != nil {
		t.Fatal(err)
	}
	if !s.useNonce(nonce) {
		t.Error("a fresh nonce was refused")
	}
	if s.useNonce(nonce) {
		t.Error("a nonce worked twice")
	}
	if s.useNonce("") || s.useNonce("made-up") {
		t.Error("an unknown nonce was accepted")
	}

	// Someone who collects nonces without using them cannot make the
	// server keep ever more of them.
	for range maxNonces + 10 {
		if _, err := s.newNonce(); err != nil {
			t.Fatal(err)
		}
	}
	s.mu.Lock()
	kept := len(s.nonces)
	s.mu.Unlock()
	if kept > maxNonces {
		t.Errorf("%d nonces are kept, want at most %d", kept, maxNonces)
	}
}

// Replacing the allowed domains (a reload) takes effect for the next order.
func TestRulesCanBeReplaced(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	client := env.registered()

	if _, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs("web.example.com")); err != nil {
		t.Fatalf("before the change: %v", err)
	}
	env.server.SetRules(policy.NewACME([]string{"other.org"}))

	_, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs("web.example.com"))
	wantProblem(t, err, "rejectedIdentifier")
	if _, err := client.AuthorizeOrder(ctx, acmeclient.DomainIDs("web.other.org")); err != nil {
		t.Errorf("the newly allowed domain: %v", err)
	}
}
