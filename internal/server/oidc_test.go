// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/oidc"
	"github.com/bastionxp/bastionxp-ca/internal/oidc/oidctest"
	"github.com/bastionxp/bastionxp-ca/internal/policy"
	"github.com/bastionxp/bastionxp-ca/internal/store"
	"github.com/bastionxp/bastionxp-ca/internal/token"
)

// corpRules are the access rules of a company with an identity provider.
func corpRules() *policy.Access {
	return policy.NewAccess([]policy.Rule{
		{Groups: []string{"linux-users"}, SSHPrincipals: []string{"{short_username}"}},
		{Groups: []string{"dba"}, SSHPrincipals: []string{"postgres"}},
		{Groups: []string{"ca-admins"}, Admin: true},
	})
}

// newOIDCTestEnv is a CA with the login switched on, against a fake
// identity provider with the corpRules.
func newOIDCTestEnv(t *testing.T) (*testEnv, *oidctest.Fake) {
	t.Helper()
	dir := t.TempDir()
	if err := ca.Init(dir, ca.InitOptions{Name: "Test", Organization: "Test Org", KeyType: ca.KeyTypeECDSA}); err != nil {
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
	authority.Record(db)

	idp := oidctest.NewFake("bastionxp-ca", "oidc-secret")
	t.Cleanup(idp.Close)

	tokens := token.New(key)
	srv := New(Options{
		CA: authority, Tokens: tokens, Store: db,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		OIDC: oidc.New(oidc.Config{
			Issuer: idp.Issuer(), ClientID: "bastionxp-ca", ClientSecret: "oidc-secret",
			UsernameClaim: "preferred_username", GroupsClaim: "groups",
		}),
		AccessRules: corpRules(),
		PublicURL:   testPublicURL,
	})
	return &testEnv{ca: authority, tokens: tokens, handler: srv.Handler(), server: srv, store: db}, idp
}

func browseOIDC(t *testing.T, env *testEnv, query url.Values) url.Values {
	t.Helper()
	return browseVia(t, env, api.OIDCLoginPath, api.OIDCCallbackPath, query)
}

// The whole road: log in at the company's identity provider, get an SSH
// certificate with the principals the person's groups give.
func TestOIDCLoginGetsPrincipalsFromGroups(t *testing.T) {
	env, idp := newOIDCTestEnv(t)
	idp.SignInAs("Alice@Corp.Example.com", "linux-users", "dba")

	result := browseOIDC(t, env, loginQuery("ssh-user"))
	grant, err := env.tokens.Verify(result.Get(api.ResultToken))
	if err != nil {
		t.Fatalf("no token: %v (%v)", err, result)
	}
	if want := []string{"alice", "postgres"}; !reflect.DeepEqual(grant.Names, want) {
		t.Errorf("principals = %v, want %v", grant.Names, want)
	}
	// The name is lower case, like the login name on Linux and in SSSD.
	if grant.Subject != "alice@corp.example.com" || grant.CreatedBy != "alice@corp.example.com" {
		t.Errorf("subject %q, created by %q", grant.Subject, grant.CreatedBy)
	}

	cert := wantSSHCert(t, env.signSSH(t, result.Get(api.ResultToken), api.SignSSHRequest{PublicKey: newSSHPublicKey(t)}))
	if cert.CertType != ssh.UserCert || !strings.HasPrefix(cert.KeyId, "alice@corp.example.com-") {
		t.Errorf("certificate: type %d, key ID %q", cert.CertType, cert.KeyId)
	}
}

// An OIDC user in no group that an access rule names is refused, by name.
func TestOIDCLoginWithoutAMatchingGroup(t *testing.T) {
	env, idp := newOIDCTestEnv(t)
	idp.SignInAs("eve@corp.example.com", "marketing")

	result := browseOIDC(t, env, loginQuery("ssh-user"))
	if !strings.Contains(result.Get(api.ResultError), "eve@corp.example.com may not use this CA") {
		t.Errorf("result = %v, want a refusal", result)
	}
}

// Leaving a group at the provider takes the principal away at the next
// login, with no change to the CA.
func TestOIDCLeavingAGroup(t *testing.T) {
	env, idp := newOIDCTestEnv(t)
	idp.SignInAs("alice@corp.example.com", "linux-users")

	result := browseOIDC(t, env, loginQuery("ssh-user", "postgres"))
	if !strings.Contains(result.Get(api.ResultError), "not allowed") {
		t.Errorf("postgres without the dba group: %v", result)
	}
}

// Membership of the admin group lets an OIDC user get host tokens, recorded
// as created by that user.
func TestOIDCAdminByGroup(t *testing.T) {
	env, idp := newOIDCTestEnv(t)
	idp.SignInAs("carol@corp.example.com", "ca-admins")

	result := browseOIDC(t, env, loginQuery("ssh-host", "web1.example.com"))
	grant, err := env.tokens.Verify(result.Get(api.ResultToken))
	if err != nil {
		t.Fatalf("no token: %v (%v)", err, result)
	}
	if grant.Template != "ssh-host" || grant.CreatedBy != "carol@corp.example.com" {
		t.Errorf("grant = %+v", grant)
	}
}

// A bad ID token at the provider's end must end in a refusal for the
// program, never in a token.
func TestOIDCLoginRefusesBadIDTokens(t *testing.T) {
	for name, tamper := range map[string]oidctest.Tamper{
		"unknown key":     oidctest.OtherKey,
		"other audience":  oidctest.OtherAudience,
		"other issuer":    oidctest.OtherIssuer,
		"expired":         oidctest.Expired,
		"other nonce":     oidctest.OtherNonce,
		"too many groups": oidctest.GroupsOverflow,
	} {
		t.Run(name, func(t *testing.T) {
			env, idp := newOIDCTestEnv(t)
			idp.SignInAs("alice@corp.example.com", "linux-users")
			idp.Misbehave(tamper)

			result := browseOIDC(t, env, loginQuery("ssh-user"))
			if result.Has(api.ResultToken) || !strings.Contains(result.Get(api.ResultError), "failed") {
				t.Errorf("result = %v, want an error and no token", result)
			}
		})
	}
}

// The PKCE verifier must never be visible to the browser: not in the
// address sent to the provider, and not in the state.
func TestOIDCVerifierNeverReachesTheBrowser(t *testing.T) {
	env, _ := newOIDCTestEnv(t)
	toIDP := redirectOf(t, env.get(t, api.OIDCLoginPath+"?"+loginQuery("ssh-user").Encode()))
	query := toIDP.Query()

	login, err := env.tokens.VerifyLogin(query.Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	if login.Provider != "oidc" {
		t.Errorf("provider = %q", login.Provider)
	}
	verifier := env.tokens.Derive("pkce-verifier", login.ID)
	if strings.Contains(toIDP.String(), verifier) {
		t.Error("the PKCE verifier is in the address sent to the browser")
	}
	if query.Get("code_challenge") == "" || query.Get("code_challenge_method") != "S256" {
		t.Errorf("no PKCE challenge: %v", query)
	}
	if query.Get("nonce") != env.tokens.Derive("oidc-nonce", login.ID) {
		t.Error("the nonce is not the one derived for this login")
	}
	if query.Get("redirect_uri") != testPublicURL+api.OIDCCallbackPath {
		t.Errorf("redirect_uri = %q", query.Get("redirect_uri"))
	}
}

// A signed login started for another provider must not be finished here.
func TestLoginForAnotherProviderIsRefused(t *testing.T) {
	env, _ := newOIDCTestEnv(t)
	other, err := env.tokens.IssueLogin(token.Login{
		Provider: "something-else", Callback: testCallback, ClientState: "x", Template: "ssh-user",
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := env.get(t, api.OIDCCallbackPath+"?"+url.Values{"code": {"x"}, "state": {other}}.Encode())
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Errorf("status %d, Location %q; want a refusal without a redirect", rec.Code, rec.Header().Get("Location"))
	}
}

// An OIDC login cancelled at the provider is reported as cancelled.
func TestOIDCPersonCancels(t *testing.T) {
	env, idp := newOIDCTestEnv(t)
	idp.SignInAs("")
	result := browseOIDC(t, env, loginQuery("ssh-user"))
	if !strings.Contains(result.Get(api.ResultError), "cancelled") {
		t.Errorf("result = %v", result)
	}
}

// When the OIDC provider is down at the start of a login, the program is
// told to try again later.
func TestOIDCProviderDown(t *testing.T) {
	env, idp := newOIDCTestEnv(t)
	idp.Close()
	back := redirectOf(t, env.get(t, api.OIDCLoginPath+"?"+loginQuery("ssh-user").Encode()))
	if back.Host != "127.0.0.1:51234" || !strings.Contains(back.Query().Get(api.ResultError), "try again later") {
		t.Errorf("redirect = %s, want an error for the program", back)
	}
}

// Replacing the access rules (a reload) takes effect for the next login.
func TestAccessRulesCanBeReplaced(t *testing.T) {
	env, idp := newOIDCTestEnv(t)
	idp.SignInAs("alice@corp.example.com", "linux-users")
	if result := browseOIDC(t, env, loginQuery("ssh-user")); !result.Has(api.ResultToken) {
		t.Fatalf("before: %v", result)
	}
	env.server.SetAccessRules(policy.NewAccess([]policy.Rule{{Groups: []string{"other"}, SSHPrincipals: []string{"x"}}}))
	if result := browseOIDC(t, env, loginQuery("ssh-user")); result.Has(api.ResultToken) {
		t.Error("after the rules changed, the login still works")
	}
}

// Without OIDC configured, the login endpoints say it is not set up (404).
func TestOIDCEndpointsWhenNotSetUp(t *testing.T) {
	env := newTestEnv(t)
	for _, path := range []string{api.OIDCLoginPath, api.OIDCCallbackPath} {
		rec := env.get(t, path+"?"+loginQuery("ssh-user").Encode())
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "not set up") {
			t.Errorf("%s: status %d, body %s", path, rec.Code, rec.Body)
		}
	}
}
