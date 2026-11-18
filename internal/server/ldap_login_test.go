// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/ldap"
	"github.com/bastionxp/bastionxp-ca/internal/ldap/ldaptest"
)

const aliceDN = "CN=Alice,OU=People,DC=corp,DC=example,DC=com"

// newLDAPTestEnv is a CA with login against a fake Active Directory, with
// the corpRules. alice is in linux-users and dba, carol in ca-admins
// (through a nested group), eve in nothing.
func newLDAPTestEnv(t *testing.T) (*testEnv, *ldaptest.Fake) {
	t.Helper()
	env := newTestEnv(t)
	dir := ldaptest.NewFake()
	t.Cleanup(dir.Close)
	carolDN := "CN=Carol,OU=People,DC=corp,DC=example,DC=com"
	dir.AddUser(ldaptest.User{DN: aliceDN, SAM: "alice", UPN: "alice@corp.example.com", Password: "alice-pw"})
	dir.AddUser(ldaptest.User{DN: carolDN, SAM: "carol", UPN: "carol@corp.example.com", Password: "carol-pw"})
	dir.AddUser(ldaptest.User{DN: "CN=Eve,OU=People,DC=corp,DC=example,DC=com", SAM: "eve", UPN: "eve@corp.example.com", Password: "eve-pw"})
	dir.AddGroup(ldaptest.Group{DN: "CN=linux-users,OU=Groups,DC=corp,DC=example,DC=com", Members: []string{aliceDN}})
	dir.AddGroup(ldaptest.Group{DN: "CN=dba,OU=Groups,DC=corp,DC=example,DC=com", Members: []string{aliceDN}})
	dir.AddGroup(ldaptest.Group{DN: "CN=pki-team,OU=Groups,DC=corp,DC=example,DC=com", Members: []string{carolDN}})
	dir.AddGroup(ldaptest.Group{DN: "CN=ca-admins,OU=Groups,DC=corp,DC=example,DC=com",
		Members: []string{"CN=pki-team,OU=Groups,DC=corp,DC=example,DC=com"}})

	srv := New(Options{
		CA: env.ca, Tokens: env.tokens, Store: env.store,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		LDAP: ldap.New(ldap.Config{
			URL: dir.URL(), RootCAs: dir.RootCAs(),
			BaseDN: ldaptest.BaseDN, BindDN: ldaptest.ServiceDN, BindPassword: ldaptest.ServicePassword,
			UserFilter: ldap.DefaultUserFilter, UsernameAttribute: ldap.DefaultUsernameAttribute,
			GroupBaseDN: ldaptest.GroupBaseDN, GroupFilter: ldap.DefaultGroupFilter,
		}),
		AccessRules: corpRules(),
	})
	env.server, env.handler = srv, srv.Handler()
	return env, dir
}

func (e *testEnv) ldapLogin(t *testing.T, req api.LDAPLoginRequest) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	httpReq := httptest.NewRequest(http.MethodPost, api.LDAPLoginPath, bytes.NewReader(data))
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, httpReq)
	return rec
}

func wantLoginToken(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body: %s)", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("a response with a token must not be cached")
	}
	var resp api.LoginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Token
}

// The whole road: a directory password, the principals from AD groups,
// an SSH certificate.
func TestLDAPLoginGetsPrincipalsFromGroups(t *testing.T) {
	env, _ := newLDAPTestEnv(t)
	pub := newSSHPublicKey(t)
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
	if err != nil {
		t.Fatal(err)
	}
	oneTime := wantLoginToken(t, env.ldapLogin(t, api.LDAPLoginRequest{
		Username: "alice", Password: "alice-pw", Template: "ssh-user", Key: ca.SSHFingerprint(parsed),
	}))
	grant, err := env.tokens.Verify(oneTime)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"alice", "postgres"}; !reflect.DeepEqual(grant.Names, want) {
		t.Errorf("principals = %v, want %v", grant.Names, want)
	}
	if grant.CreatedBy != "alice@corp.example.com" || time.Until(grant.Expires) > time.Minute {
		t.Errorf("grant = %+v, want made by alice, for one minute", grant)
	}
	cert := wantSSHCert(t, env.signSSH(t, oneTime, api.SignSSHRequest{PublicKey: pub}))
	if !strings.HasPrefix(cert.KeyId, "alice@corp.example.com-") {
		t.Errorf("key ID = %q", cert.KeyId)
	}
}

// Membership of the admin group through a nested group lets an LDAP user get
// a token for a server, valid for the time asked.
func TestLDAPAdminByNestedGroup(t *testing.T) {
	env, _ := newLDAPTestEnv(t)
	oneTime := wantLoginToken(t, env.ldapLogin(t, api.LDAPLoginRequest{
		Username: "carol", Password: "carol-pw", Template: "tls-server", Names: []string{"web1.example.com"}, ValidFor: "1h",
	}))
	grant, err := env.tokens.Verify(oneTime)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Template != "tls-server" || time.Until(grant.Expires) < 50*time.Minute {
		t.Errorf("grant = %+v", grant)
	}
}

// LDAP logins are refused, with status and message, for a wrong or empty
// password, an unknown person, no matching rule, a non-admin asking for a
// host certificate, a principal not given, a bad profile and a bad validity.
func TestLDAPLoginRefusals(t *testing.T) {
	env, _ := newLDAPTestEnv(t)
	tests := []struct {
		name   string
		req    api.LDAPLoginRequest
		status int
		text   string
	}{
		{"wrong password", api.LDAPLoginRequest{Username: "alice", Password: "nope", Template: "ssh-user"}, 401, "invalid username or password"},
		{"empty password", api.LDAPLoginRequest{Username: "alice", Template: "ssh-user"}, 401, "invalid username or password"},
		{"unknown person", api.LDAPLoginRequest{Username: "mallory", Password: "x", Template: "ssh-user"}, 401, "invalid username or password"},
		{"no rule", api.LDAPLoginRequest{Username: "eve", Password: "eve-pw", Template: "ssh-user"}, 403, "may not use this CA"},
		{"not an admin", api.LDAPLoginRequest{Username: "alice", Password: "alice-pw", Template: "ssh-host", Names: []string{"web1"}}, 403, "not allowed"},
		{"principal not given", api.LDAPLoginRequest{Username: "alice", Password: "alice-pw", Template: "ssh-user", Names: []string{"root"}}, 403, "not allowed"},
		{"bad profile", api.LDAPLoginRequest{Username: "alice", Password: "alice-pw", Template: "x"}, 400, "profile"},
		{"bad validity", api.LDAPLoginRequest{Username: "alice", Password: "alice-pw", Template: "ssh-user", ValidFor: "soon"}, 400, "validity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantError(t, env.ldapLogin(t, tt.req), tt.status, tt.text)
		})
	}
}

// After repeated wrong passwords, LDAP logins for the name are refused with
// 429 even with the right password.
func TestLDAPTooManyFailures(t *testing.T) {
	env, _ := newLDAPTestEnv(t)
	for range 3 {
		wantError(t, env.ldapLogin(t, api.LDAPLoginRequest{Username: "alice", Password: "nope", Template: "ssh-user"}), 401, "invalid")
	}
	wantError(t, env.ldapLogin(t, api.LDAPLoginRequest{Username: "alice", Password: "alice-pw", Template: "ssh-user"}), 429, "too many")
}

// When the directory is down, an LDAP login gets 502 and a message about the
// directory.
func TestLDAPDirectoryDown(t *testing.T) {
	env, dir := newLDAPTestEnv(t)
	dir.Close()
	wantError(t, env.ldapLogin(t, api.LDAPLoginRequest{Username: "alice", Password: "alice-pw", Template: "ssh-user"}), 502, "directory")
}

// Without LDAP configured, the LDAP login endpoint says it is not set up
// (404).
func TestLDAPLoginNotSetUp(t *testing.T) {
	env := newTestEnv(t)
	wantError(t, env.ldapLogin(t, api.LDAPLoginRequest{Username: "alice", Password: "alice-pw", Template: "ssh-user"}), 404, "not set up")
}
