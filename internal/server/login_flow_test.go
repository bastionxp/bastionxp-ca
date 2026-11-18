// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/oidc"
	"github.com/bastionxp/bastionxp-ca/internal/oidc/oidctest"
	"github.com/bastionxp/bastionxp-ca/internal/policy"
	"github.com/bastionxp/bastionxp-ca/internal/store"
	"github.com/bastionxp/bastionxp-ca/internal/token"
)

const (
	testPublicURL = "https://ca.test:8443"
	// testCallback is where the program on the person's machine listens.
	testCallback = "http://127.0.0.1:51234/callback"
)

// newLoginTestEnv is like newTestEnv, with the browser login switched on,
// against a fake identity provider: ganesh is an admin, alice is a user
// who may log in to servers as "alice" and "deploy".
func newLoginTestEnv(t *testing.T) (*testEnv, *oidctest.Fake) {
	t.Helper()
	dir := t.TempDir()

	err := ca.Init(dir, ca.InitOptions{Name: "Test", Organization: "Test Org", KeyType: ca.KeyTypeECDSA})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := ca.Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := token.LoadOrCreateKey(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(dir, store.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	fake := oidctest.NewFake("test-client-id", "test-client-secret")
	t.Cleanup(fake.Close)

	tokens := token.New(key)
	srv := New(Options{
		CA:     authority,
		Tokens: tokens,
		Store:  db,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		OIDC: oidc.New(oidc.Config{
			Issuer: fake.Issuer(), ClientID: "test-client-id", ClientSecret: "test-client-secret",
			UsernameClaim: "preferred_username", GroupsClaim: "groups",
		}),
		AccessRules: policy.NewAccess([]policy.Rule{
			{Users: []string{"ganesh"}, Admin: true},
			{Users: []string{"alice"}, SSHPrincipals: []string{"alice", "deploy"}},
		}),
		PublicURL: testPublicURL,
	})
	return &testEnv{ca: authority, tokens: tokens, handler: srv.Handler(), server: srv, store: db}, fake
}

// get sends a GET request to the CA, as a browser would, and returns the
// response without following a redirect.
func (e *testEnv) get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

// redirectOf returns where a response sends the browser.
func redirectOf(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want a redirect (body: %s)", rec.Code, rec.Body)
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// loginQuery returns the parameters a program sends to start a login.
func loginQuery(template string, names ...string) url.Values {
	return url.Values{
		api.LoginCallback: {testCallback},
		api.LoginState:    {"client-state"},
		api.LoginProfile:  {template},
		api.LoginName:     names,
	}
}

// browse plays the person's browser through a whole login: the CA's
// login address, the provider, the CA's callback address. It returns the result
// the CA sends to the program on the person's machine.
func browse(t *testing.T, env *testEnv, query url.Values) url.Values {
	t.Helper()
	return browseVia(t, env, api.OIDCLoginPath, api.OIDCCallbackPath, query)
}

// browseVia is browse with explicit login and callback paths.
func browseVia(t *testing.T, env *testEnv, loginPath, callbackPath string, query url.Values) url.Values {
	t.Helper()

	// 1. The CA sends the browser to the provider.
	toProvider := redirectOf(t, env.get(t, loginPath+"?"+query.Encode()))

	// 2. The provider (the fake) sends it back to the CA.
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := noFollow.Get(toProvider.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("the provider answered %s, want a redirect", resp.Status)
	}
	toCA, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := toCA.Scheme + "://" + toCA.Host + toCA.Path; got != testPublicURL+callbackPath {
		t.Fatalf("the provider sent the browser to %s, want the CA's callback address", got)
	}

	// 3. The CA sends it to the program on the person's own machine.
	rec := env.get(t, toCA.RequestURI())
	toProgram := redirectOf(t, rec)
	if got := toProgram.Scheme + "://" + toProgram.Host + toProgram.Path; got != testCallback {
		t.Fatalf("the CA sent the result to %s, want %s", got, testCallback)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("the response with the token may be cached or leak in a Referer header: %v", rec.Header())
	}
	result := toProgram.Query()
	if result.Get(api.ResultState) != query.Get(api.LoginState) {
		t.Errorf("state = %q, want the program's own %q", result.Get(api.ResultState), query.Get(api.LoginState))
	}
	if result.Has(api.ResultToken) == result.Has(api.ResultError) {
		t.Fatalf("the result must have a token or an error, and not both: %v", result)
	}
	return result
}

// The whole road for a user: log in, get a token, get an SSH certificate.
func TestUserGetsOwnSSHCertificate(t *testing.T) {
	env, fake := newLoginTestEnv(t)
	fake.SignInAs("alice")

	publicKey := newSSHPublicKey(t)
	parsedKey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(publicKey))

	// The user names nothing but the template and their key.
	query := loginQuery("ssh-user")
	query.Set(api.LoginKey, ca.SSHFingerprint(parsedKey))
	result := browse(t, env, query)

	grant, err := env.tokens.Verify(result.Get(api.ResultToken))
	if err != nil {
		t.Fatal(err)
	}
	if grant.Subject != "alice" || grant.CreatedBy != "alice" {
		t.Errorf("subject = %q, created by = %q; want alice for both", grant.Subject, grant.CreatedBy)
	}
	if want := []string{"alice", "deploy"}; !reflect.DeepEqual(grant.Names, want) {
		t.Errorf("names = %v, want %v", grant.Names, want)
	}
	if left := time.Until(grant.Expires); left > keyTokenValidity || left < keyTokenValidity-10*time.Second {
		t.Errorf("token ends in %s, want about %s", left, keyTokenValidity)
	}

	cert := wantSSHCert(t, env.signSSH(t, result.Get(api.ResultToken), api.SignSSHRequest{PublicKey: publicKey}))
	if cert.CertType != ssh.UserCert {
		t.Errorf("certificate type = %d, want a user certificate", cert.CertType)
	}
	if want := []string{"alice", "deploy"}; !reflect.DeepEqual(cert.ValidPrincipals, want) {
		t.Errorf("principals = %v, want %v", cert.ValidPrincipals, want)
	}
	// The key ID names the person, so SSH servers log who it was.
	if want := "alice-" + grant.ID; cert.KeyId != want {
		t.Errorf("key ID = %q, want %q", cert.KeyId, want)
	}
}

// A token from a login is tied to the key it was asked for. Whoever
// gets hold of it cannot use it for a key of their own.
func TestTokenFromLoginOnlyWorksForItsKey(t *testing.T) {
	env, fake := newLoginTestEnv(t)
	fake.SignInAs("alice")

	aliceKey := newSSHPublicKey(t)
	parsedKey, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(aliceKey))
	query := loginQuery("ssh-user")
	query.Set(api.LoginKey, ca.SSHFingerprint(parsedKey))
	oneTime := browse(t, env, query).Get(api.ResultToken)

	thiefKey := newSSHPublicKey(t)
	rec := env.signSSH(t, oneTime, api.SignSSHRequest{PublicKey: thiefKey})
	wantError(t, rec, http.StatusForbidden, "another key")

	// The refusal did not use up the token: its owner can still use it.
	wantSSHCert(t, env.signSSH(t, oneTime, api.SignSSHRequest{PublicKey: aliceKey}))
}

// A TLS token from a browser login that names the key's fingerprint works
// only for a CSR of that key, not for another key with the same names.
func TestTLSTokenFromLoginOnlyWorksForItsKey(t *testing.T) {
	env, fake := newLoginTestEnv(t)
	fake.SignInAs("ganesh")

	// The admin's program makes a key and sends its fingerprint along.
	csrPEM := newCSR(t, "", "web.example.com")
	csr, err := parseCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := ca.X509Fingerprint(csr.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	query := loginQuery("tls-server", "web.example.com")
	query.Set(api.LoginKey, fingerprint)
	oneTime := browse(t, env, query).Get(api.ResultToken)

	otherCSR := newCSR(t, "", "web.example.com") // same names, another key
	wantError(t, env.sign(t, oneTime, api.SignX509Request{CSR: otherCSR}), http.StatusForbidden, "another key")

	rec := env.sign(t, oneTime, api.SignX509Request{CSR: csrPEM})
	if rec.Code != http.StatusCreated {
		t.Errorf("own key: status = %d, want 201 (body: %s)", rec.Code, rec.Body)
	}
}

// A user who logs in cannot get someone else's principal or subject, a host
// certificate, or a TLS certificate: each is not allowed.
func TestUserCannotGetWhatIsNotTheirs(t *testing.T) {
	env, fake := newLoginTestEnv(t)
	fake.SignInAs("alice")

	withSubject := loginQuery("ssh-user")
	withSubject.Set(api.LoginSubject, "ganesh")

	tests := map[string]url.Values{
		"principal of someone else": loginQuery("ssh-user", "root"),
		"own and other principal":   loginQuery("ssh-user", "alice", "root"),
		"subject of someone else":   withSubject,
		"host certificate":          loginQuery("ssh-host", "web1.example.com"),
		"TLS certificate":           loginQuery("tls-server", "web.example.com"),
	}
	for name, query := range tests {
		t.Run(name, func(t *testing.T) {
			result := browse(t, env, query)
			if !strings.Contains(result.Get(api.ResultError), "not allowed") {
				t.Errorf("result = %v, want an error that says 'not allowed'", result)
			}
		})
	}
}

// A correct login at the provider by someone not in the CA's configuration
// is refused, by name.
func TestLoginRefusesPeopleNotInTheConfiguration(t *testing.T) {
	env, fake := newLoginTestEnv(t)
	// A real account, with a correct login at the provider, who is not
	// named in the CA's configuration.
	fake.SignInAs("mallory")

	result := browse(t, env, loginQuery("ssh-user"))
	if !strings.Contains(result.Get(api.ResultError), "mallory may not use this CA") {
		t.Errorf("result = %v, want a refusal for mallory", result)
	}
}

// A login cancelled at the provider is reported to the program as cancelled.
func TestPersonCancelsAtTheProvider(t *testing.T) {
	env, fake := newLoginTestEnv(t)
	fake.SignInAs("") // presses Cancel

	result := browse(t, env, loginQuery("ssh-user"))
	if !strings.Contains(result.Get(api.ResultError), "cancelled") {
		t.Errorf("result = %v, want an error that says the login was cancelled", result)
	}
}

// An admin's login gets a token for a server: for the subject chosen,
// created by the admin, bound to no key, valid for the time asked; it gets a
// host certificate.
func TestAdminGetsTokensForOthers(t *testing.T) {
	env, fake := newLoginTestEnv(t)
	fake.SignInAs("ganesh")

	// A token to hand to a server: no key, and valid for a chosen time.
	query := loginQuery("ssh-host", "web1.example.com")
	query.Set(api.LoginValidFor, "1h")
	oneTime := browse(t, env, query).Get(api.ResultToken)

	grant, err := env.tokens.Verify(oneTime)
	if err != nil {
		t.Fatal(err)
	}
	// Who the token is for and who created it are kept apart.
	if grant.Subject != "web1.example.com" || grant.CreatedBy != "ganesh" {
		t.Errorf("subject = %q, created by = %q; want web1.example.com and ganesh", grant.Subject, grant.CreatedBy)
	}
	if grant.KeyFingerprint != "" {
		t.Errorf("key fingerprint = %q, want none", grant.KeyFingerprint)
	}
	if left := time.Until(grant.Expires); left < 59*time.Minute || left > time.Hour {
		t.Errorf("token ends in %s, want about 1h", left)
	}
	cert := wantSSHCert(t, env.signSSH(t, oneTime, api.SignSSHRequest{PublicKey: newSSHPublicKey(t)}))
	if cert.CertType != ssh.HostCert {
		t.Errorf("certificate type = %d, want a host certificate", cert.CertType)
	}

	// With a subject the admin chose.
	query = loginQuery("tls-server", "web.example.com")
	query.Set(api.LoginSubject, "web-team")
	grant, err = env.tokens.Verify(browse(t, env, query).Get(api.ResultToken))
	if err != nil {
		t.Fatal(err)
	}
	if grant.Subject != "web-team" {
		t.Errorf("subject = %q, want web-team", grant.Subject)
	}
}

// Bad login requests are reported back to the program: an unknown profile or
// token validity before the trip to the provider; no names, a validity above
// the maximum, or a subject with a space after it.
func TestLoginReportsBadRequestsToTheProgram(t *testing.T) {
	env, fake := newLoginTestEnv(t)
	fake.SignInAs("ganesh")

	badValidFor := loginQuery("tls-server", "a.example.com")
	badValidFor.Set(api.LoginValidFor, "soon")
	tooLong := loginQuery("tls-server", "a.example.com")
	tooLong.Set(api.LoginValidFor, "48h")
	badSubject := loginQuery("tls-server", "a.example.com")
	badSubject.Set(api.LoginSubject, "web team")

	// These two are caught before the trip to the provider.
	early := map[string]struct {
		query    url.Values
		wantText string
	}{
		"unknown profile":    {loginQuery("tls-everything", "a"), "profile"},
		"bad token validity": {badValidFor, "validity"},
	}
	for name, tt := range early {
		t.Run(name, func(t *testing.T) {
			back := redirectOf(t, env.get(t, api.OIDCLoginPath+"?"+tt.query.Encode()))
			if back.Host != "127.0.0.1:51234" || !strings.Contains(back.Query().Get(api.ResultError), tt.wantText) {
				t.Errorf("redirect = %s, want an error about %q sent to the program", back, tt.wantText)
			}
		})
	}

	// These are caught after it, when the token is made.
	late := map[string]struct {
		query    url.Values
		wantText string
	}{
		"no names":                {loginQuery("tls-server"), "at least one name"},
		"token validity too long": {tooLong, "above the maximum"},
		"subject with a space":    {badSubject, "subject"},
	}
	for name, tt := range late {
		t.Run(name, func(t *testing.T) {
			result := browse(t, env, tt.query)
			if !strings.Contains(result.Get(api.ResultError), tt.wantText) {
				t.Errorf("result = %v, want an error about %q", result, tt.wantText)
			}
		})
	}
}

// The callback is where a person's token is sent after an honest login.
// If the CA accepted an address that is not on the person's own machine,
// a link to the real CA could be used to steal tokens.
func TestLoginOnlyAcceptsCallbacksOnTheSameMachine(t *testing.T) {
	env, fake := newLoginTestEnv(t)
	fake.SignInAs("alice")

	bad := []string{
		"",
		"https://attacker.example/",
		"http://attacker.example/",
		"http://attacker.example:51234/callback",
		"https://127.0.0.1:51234/callback",          // not plain http
		"http://127.0.0.1/callback",                 // no port
		"http://localhost:51234/callback",           // a name, not the address
		"http://127.0.0.1.attacker.example:80/",     // only looks like it
		"http://127.0.0.1:51234@attacker.example/",  // the real host is after the @
		"http://attacker.example@127.0.0.1:51234/",  // a user name in the address
		"http://attacker.example#@127.0.0.1:51234/", // tricks with #
		"http://2130706433:51234/",                  // 127.0.0.1 written as a number
		"http://0x7f.0.0.1:51234/",                  // and in hex
		"http://127.1:51234/",                       // and shortened
		"http://[::1]:51234/callback",               // IPv6: not accepted, to keep one form
		"http://0.0.0.0:51234/",
		"http://192.168.1.10:51234/",
		"//attacker.example/",
		"javascript:alert(1)",
		"http://127.0.0.1:51234/" + strings.Repeat("a", maxLoginParamLength),
	}
	for _, callback := range bad {
		t.Run(callback, func(t *testing.T) {
			query := loginQuery("ssh-user")
			query.Set(api.LoginCallback, callback)
			rec := env.get(t, api.OIDCLoginPath+"?"+query.Encode())

			// Refused on the spot, with a page and not a redirect:
			// the browser must not be sent anywhere.
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
			if location := rec.Header().Get("Location"); location != "" {
				t.Errorf("the browser is sent to %s", location)
			}
		})
	}

	good := []string{
		"http://127.0.0.1:51234/callback",
		"http://127.0.0.1:8080/",
		"http://127.0.0.1:1/a/b",
	}
	for _, callback := range good {
		if _, ok := loopbackCallback(callback); !ok {
			t.Errorf("%s is refused, want it accepted", callback)
		}
	}
}

// A login without a state is refused with 400.
func TestLoginNeedsAState(t *testing.T) {
	env, _ := newLoginTestEnv(t)
	query := loginQuery("ssh-user")
	query.Del(api.LoginState)
	rec := env.get(t, api.OIDCLoginPath+"?"+query.Encode())
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// The second address a browser reaches, the callback, must not trust
// anything that the CA did not sign itself at the first one.
func TestCallbackOnlyAcceptsLoginsTheCAStarted(t *testing.T) {
	env, fake := newLoginTestEnv(t)
	fake.SignInAs("alice")

	// A login signed by another CA, with a callback that would send the
	// token to an attacker.
	otherEnv := newTestEnv(t)
	forged, err := otherEnv.tokens.IssueLogin(token.Login{
		Callback: "https://attacker.example/", ClientState: "x", Template: "ssh-user", Provider: "oidc",
	})
	if err != nil {
		t.Fatal(err)
	}
	// A real one-time token of this CA in place of the state.
	oneTime := env.issueToken(t, "ssh-user", "alice")

	for name, state := range map[string]string{
		"no state":             "",
		"made-up state":        "hello",
		"signed by another CA": forged,
		"a one-time token":     oneTime,
	} {
		t.Run(name, func(t *testing.T) {
			query := url.Values{"code": {"some-code"}, "state": {state}}
			rec := env.get(t, api.OIDCCallbackPath+"?"+query.Encode())
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
			if location := rec.Header().Get("Location"); location != "" {
				t.Errorf("the browser is sent to %s", location)
			}
		})
	}
}

// Someone who builds the callback address by hand, with a state the CA
// did sign but a code the provider never gave out, gets no token.
func TestCallbackWithAMadeUpCode(t *testing.T) {
	env, fake := newLoginTestEnv(t)
	fake.SignInAs("alice")

	toProvider := redirectOf(t, env.get(t, api.OIDCLoginPath+"?"+loginQuery("ssh-user").Encode()))
	state := toProvider.Query().Get("state")

	for _, code := range []string{"", "made-up-code"} {
		query := url.Values{"code": {code}, "state": {state}}
		result := redirectOf(t, env.get(t, api.OIDCCallbackPath+"?"+query.Encode())).Query()
		if result.Has(api.ResultToken) || !strings.Contains(result.Get(api.ResultError), "failed") {
			t.Errorf("code %q: result = %v, want an error and no token", code, result)
		}
	}
}

// The login address sends the browser to the provider with the right
// parameters, and without the client secret.
func TestLoginSendsTheBrowserToTheProvider(t *testing.T) {
	env, _ := newLoginTestEnv(t)

	toProvider := redirectOf(t, env.get(t, api.OIDCLoginPath+"?"+loginQuery("ssh-user").Encode()))
	query := toProvider.Query()
	if query.Get("client_id") != "test-client-id" {
		t.Errorf("client_id = %q", query.Get("client_id"))
	}
	if got, want := query.Get("redirect_uri"), testPublicURL+api.OIDCCallbackPath; got != want {
		t.Errorf("redirect_uri = %q, want %q", got, want)
	}
	if strings.Contains(toProvider.String(), "test-client-secret") {
		t.Error("the client secret is in an address sent to the browser")
	}
	// The state is a login this CA can read back.
	login, err := env.tokens.VerifyLogin(query.Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	if login.Callback != testCallback || login.ClientState != "client-state" || login.Template != "ssh-user" {
		t.Errorf("login = %+v", login)
	}
}

// When the provider is down at the callback, the program is told to try
// again later.
func TestLoginWhenTheProviderIsDown(t *testing.T) {
	env, fake := newLoginTestEnv(t)
	fake.SignInAs("alice")

	toProvider := redirectOf(t, env.get(t, api.OIDCLoginPath+"?"+loginQuery("ssh-user").Encode()))
	fake.Close()

	query := url.Values{"code": {"some-code"}, "state": {toProvider.Query().Get("state")}}
	result := redirectOf(t, env.get(t, api.OIDCCallbackPath+"?"+query.Encode())).Query()
	if !strings.Contains(result.Get(api.ResultError), "try again later") {
		t.Errorf("result = %v, want an error that says to try again later", result)
	}
}

// Without a login configured, the login endpoints say it is not set up
// (404).
func TestLoginEndpointsWhenNotSetUp(t *testing.T) {
	env := newTestEnv(t) // no login
	for _, path := range []string{api.OIDCLoginPath, api.OIDCCallbackPath} {
		rec := env.get(t, path+"?"+loginQuery("ssh-user").Encode())
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "not set up") {
			t.Errorf("%s: status = %d, body = %s; want 404 and 'not set up'", path, rec.Code, rec.Body)
		}
	}
}

// A signed login is not a one-time token. It must not work at the sign
// endpoints, although it names a template and names like a token does.
func TestSignedLoginIsNotAOneTimeToken(t *testing.T) {
	env, _ := newLoginTestEnv(t)
	toProvider := redirectOf(t, env.get(t, api.OIDCLoginPath+"?"+loginQuery("ssh-user", "root").Encode()))
	state := toProvider.Query().Get("state")

	rec := env.signSSH(t, state, api.SignSSHRequest{PublicKey: newSSHPublicKey(t)})
	wantError(t, rec, http.StatusUnauthorized, "token")
}

// The rules can change while the server runs: someone taken out of the
// configuration cannot log in any more, without a restart.
func TestRulesCanBeReplaced(t *testing.T) {
	env, fake := newLoginTestEnv(t)
	fake.SignInAs("alice")
	if result := browse(t, env, loginQuery("ssh-user")); !result.Has(api.ResultToken) {
		t.Fatalf("before the change: %v", result)
	}

	env.server.SetAccessRules(policy.NewAccess([]policy.Rule{{Users: []string{"bob"}, SSHPrincipals: []string{"bob"}}}))

	result := browse(t, env, loginQuery("ssh-user"))
	if !strings.Contains(result.Get(api.ResultError), "alice may not use this CA") {
		t.Errorf("after alice was removed: %v", result)
	}
	fake.SignInAs("bob")
	if result := browse(t, env, loginQuery("ssh-user")); !result.Has(api.ResultToken) {
		t.Errorf("bob, who was added: %v", result)
	}
}
