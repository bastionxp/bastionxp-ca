// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"reflect"
	"slices"
	"testing"
)

func gh(login string) Identity { return Identity{Source: "oidc", Username: login} }

func newTestUsers() *Access {
	return NewAccess([]Rule{
		{Users: []string{"Ganesh"}, Admin: true},
		{Users: []string{"alice"}, SSHPrincipals: []string{"alice", "deploy"}},
		{Users: []string{"ganesh"}, SSHPrincipals: []string{"ganesh"}},
	})
}

// Who may log in and who is an admin, by name, ignoring case.
func TestMayLogInAndIsAdmin(t *testing.T) {
	g := newTestUsers()
	tests := []struct {
		login    string
		mayLogIn bool
		isAdmin  bool
	}{
		{"alice", true, false},
		{"ALICE", true, false}, // names ignore case
		{"ganesh", true, true},
		{"Ganesh", true, true},
		{"mallory", false, false},
		{"", false, false},
	}
	for _, tt := range tests {
		if got := g.MayLogIn(gh(tt.login)); got != tt.mayLogIn {
			t.Errorf("MayLogIn(%q) = %v, want %v", tt.login, got, tt.mayLogIn)
		}
		if got := g.IsAdmin(gh(tt.login)); got != tt.isAdmin {
			t.Errorf("IsAdmin(%q) = %v, want %v", tt.login, got, tt.isAdmin)
		}
	}
}

// An admin who is listed for nothing else may still log in.
func TestAdminWithoutPrincipalsMayLogIn(t *testing.T) {
	g := NewAccess([]Rule{{Users: []string{"root-admin"}, Admin: true}})
	if !g.MayLogIn(gh("root-admin")) {
		t.Error("an admin who is not listed as a user must still be able to log in")
	}
}

// A user gets a token for all or some of their own principals, always with
// themselves as the subject, whatever the case of their login.
func TestAuthorizeTokenForThemselves(t *testing.T) {
	g := newTestUsers()
	tests := []struct {
		name      string
		login     string
		req       TokenRequest
		wantNames []string
	}{
		{"no names: all of their own", "alice", TokenRequest{Template: "ssh-user"}, []string{"alice", "deploy"}},
		{"one of their own", "alice", TokenRequest{Template: "ssh-user", Names: []string{"deploy"}}, []string{"deploy"}},
		{"own login as subject", "alice", TokenRequest{Template: "ssh-user", Subject: "Alice"}, []string{"alice", "deploy"}},
		{"login in another case", "Alice", TokenRequest{Template: "ssh-user"}, []string{"alice", "deploy"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := g.AuthorizeToken(gh(tt.login), sshOnly, tt.req)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Names, tt.wantNames) {
				t.Errorf("names = %v, want %v", got.Names, tt.wantNames)
			}
			// The subject is always the person who logged in.
			if got.Subject != tt.login {
				t.Errorf("subject = %q, want %q", got.Subject, tt.login)
			}
		})
	}
}

// A user is refused someone else's principal or subject, a host certificate,
// TLS certificates, and so is an unknown or empty login; a refusal returns
// nothing.
func TestAuthorizeTokenRefusesUsersWhatIsNotTheirs(t *testing.T) {
	g := newTestUsers()
	tests := []struct {
		name  string
		login string
		req   TokenRequest
	}{
		{"principal of someone else", "alice", TokenRequest{Template: "ssh-user", Names: []string{"root"}}},
		{"one own and one other principal", "alice", TokenRequest{Template: "ssh-user", Names: []string{"alice", "root"}}},
		{"subject of someone else", "alice", TokenRequest{Template: "ssh-user", Subject: "ganesh"}},
		{"host certificate", "alice", TokenRequest{Template: "ssh-host", Names: []string{"alice"}}},
		{"TLS server certificate", "alice", TokenRequest{Template: "tls-server", Names: []string{"web.example.com"}}},
		{"TLS client certificate with own name", "alice", TokenRequest{Template: "tls-client", Names: []string{"alice"}}},
		{"unknown person", "mallory", TokenRequest{Template: "ssh-user"}},
		{"empty login", "", TokenRequest{Template: "ssh-user"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := g.AuthorizeToken(gh(tt.login), sshOnly, tt.req)
			if !errors.Is(err, ErrNotAllowed) {
				t.Errorf("error = %v, want ErrNotAllowed", err)
			}
			if got.Template != "" || len(got.Names) != 0 {
				t.Errorf("a refused request returned %+v", got)
			}
		})
	}
}

// An admin may create a token for any profile, names and subject.
func TestAuthorizeTokenLetsAdminsCreateAnything(t *testing.T) {
	g := newTestUsers()
	for _, req := range []TokenRequest{
		{Template: "ssh-host", Names: []string{"web1.example.com"}},
		{Template: "tls-server", Names: []string{"web.example.com"}, Subject: "web-team"},
		{Template: "ssh-user", Names: []string{"root"}},
	} {
		got, err := g.AuthorizeToken(gh("ganesh"), sshOnly, req)
		if err != nil || !reflect.DeepEqual(got, req) {
			t.Errorf("%+v: got %+v, %v", req, got, err)
		}
	}
}

// ---- Rules by group, as the OIDC login uses them ----

func corpRules() *Access {
	return NewAccess([]Rule{
		{Groups: []string{"linux-users"}, SSHPrincipals: []string{"{short_username}"}},
		{Groups: []string{"dba"}, SSHPrincipals: []string{"{short_username}", "postgres"}},
		{Groups: []string{"ca-admins"}, Admin: true},
		{Users: []string{"bob@corp.example.com"}, SSHPrincipals: []string{"{username}", "deploy"}},
	})
}

func oidcID(username string, groups ...string) Identity {
	return Identity{Source: "oidc", Username: username, Groups: groups}
}

// Access rules by group and by name: rules add up with each principal once,
// group names ignore case, an admin rule gives only admin, and no matching
// group gives nothing.
func TestRulesByGroup(t *testing.T) {
	a := corpRules()
	tests := []struct {
		name  string
		id    Identity
		want  []string
		admin bool
	}{
		{"one group", oidcID("alice@corp.example.com", "linux-users"), []string{"alice"}, false},
		// Rules add up, and a principal comes only once.
		{"two groups", oidcID("alice@corp.example.com", "linux-users", "dba"), []string{"alice", "postgres"}, false},
		{"group names ignore case", oidcID("alice@corp.example.com", "Linux-Users"), []string{"alice"}, false},
		{"admin only", oidcID("carol@corp.example.com", "ca-admins"), nil, true},
		{"by name", oidcID("Bob@corp.example.com"), []string{"Bob@corp.example.com", "deploy"}, false},
		{"no matching group", oidcID("eve@corp.example.com", "marketing"), nil, false},
		{"no groups at all", oidcID("eve@corp.example.com"), nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.principals(tt.id); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("principals = %v, want %v", got, tt.want)
			}
			if got := a.IsAdmin(tt.id); got != tt.admin {
				t.Errorf("admin = %v, want %v", got, tt.admin)
			}
			if got := a.MayLogIn(tt.id); got != (len(tt.want) > 0 || tt.admin) {
				t.Errorf("may log in = %v", got)
			}
		})
	}
}

// Being in a group with a name like someone's login must not make the
// person that someone, and the reverse.
func TestNamesAndGroupsAreKeptApart(t *testing.T) {
	a := NewAccess([]Rule{
		{Users: []string{"admin"}, Admin: true},
		{Groups: []string{"ops"}, SSHPrincipals: []string{"ops"}},
	})
	if a.IsAdmin(oidcID("alice@corp.example.com", "admin")) {
		t.Error("a group called admin made someone the user admin")
	}
	if a.MayLogIn(oidcID("ops")) {
		t.Error("a person called ops got the rights of the group ops")
	}
}

// {short_username} for a username without @ is the whole username.
func TestShortUsernameWithoutAt(t *testing.T) {
	a := NewAccess([]Rule{{Groups: []string{"g"}, SSHPrincipals: []string{"{short_username}"}}})
	if got := a.principals(oidcID("alice", "g")); !reflect.DeepEqual(got, []string{"alice"}) {
		t.Errorf("principals = %v, want [alice]", got)
	}
}

// Tokens follow the groups: a group's principals are given, leaving the
// group takes them away, and an admin by group may hand out anything.
func TestAuthorizeTokenWithGroups(t *testing.T) {
	a := corpRules()

	got, err := a.AuthorizeToken(oidcID("alice@corp.example.com", "dba"), sshOnly, TokenRequest{Template: "ssh-user"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Names, []string{"alice", "postgres"}) || got.Subject != "alice@corp.example.com" {
		t.Errorf("got %+v", got)
	}

	// Leaving the group in the directory takes the principal away.
	if _, err := a.AuthorizeToken(oidcID("alice@corp.example.com", "linux-users"), sshOnly, TokenRequest{Template: "ssh-user", Names: []string{"postgres"}}); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("postgres without the dba group: error = %v, want ErrNotAllowed", err)
	}

	// An admin by group may hand out anything.
	if _, err := a.AuthorizeToken(oidcID("carol@corp.example.com", "ca-admins"), sshOnly, TokenRequest{Template: "ssh-host", Names: []string{"web1"}}); err != nil {
		t.Errorf("admin by group: %v", err)
	}
}

// The rules a policy was made with cannot be changed from outside.
func TestNewAccessCopiesTheRules(t *testing.T) {
	rules := []Rule{{Groups: []string{"g"}, SSHPrincipals: []string{"p"}}}
	a := NewAccess(rules)
	rules[0] = Rule{Groups: []string{"g"}, Admin: true}
	if a.IsAdmin(oidcID("x", "g")) {
		t.Error("changing the caller's slice changed the policy")
	}
}

// sshOnly is a login that gives people SSH user certificates only.
var sshOnly = Own{SSHProfile: "ssh-user"}

// What a login verifier gives people for themselves: its SSH profile for
// their own principals, and its X.509 profile for their own name only.
func TestAuthorizeOwnCertificates(t *testing.T) {
	a := NewAccess([]Rule{
		{Groups: []string{"employees"}, SSHPrincipals: []string{"{short_username}"}},
		{Groups: []string{"ca-admins"}, Admin: true},
	})
	alice := oidcID("alice@corp.example.com", "employees")
	own := Own{SSHProfile: "ops-ssh", X509Profile: "user-client"}

	// SSH: the verifier's profile, not another.
	got, err := a.AuthorizeToken(alice, own, TokenRequest{Template: "ops-ssh"})
	if err != nil || len(got.Names) != 1 || got.Names[0] != "alice" {
		t.Errorf("own SSH: %+v, %v", got, err)
	}
	if _, err := a.AuthorizeToken(alice, own, TokenRequest{Template: "ssh-user"}); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("another SSH profile: %v", err)
	}

	// TLS: their own name, decided for them.
	got, err = a.AuthorizeToken(alice, own, TokenRequest{Template: "user-client"})
	if err != nil || len(got.Names) != 1 || got.Names[0] != "alice@corp.example.com" || got.Subject != "alice@corp.example.com" {
		t.Errorf("own client certificate: %+v, %v", got, err)
	}
	if _, err := a.AuthorizeToken(alice, own, TokenRequest{Template: "user-client", Names: []string{"ALICE@corp.example.com"}}); err != nil {
		t.Errorf("own name in other case: %v", err)
	}
	for name, req := range map[string]TokenRequest{
		"someone else's name": {Template: "user-client", Names: []string{"bob@corp.example.com"}},
		"an extra name":       {Template: "user-client", Names: []string{"alice@corp.example.com", "web.example.com"}},
		"another profile":     {Template: "tls-server", Names: []string{"alice@corp.example.com"}},
		"another subject":     {Template: "user-client", Subject: "bob@corp.example.com"},
	} {
		if _, err := a.AuthorizeToken(alice, own, req); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A verifier without an X.509 profile gives no client certificates.
	if _, err := a.AuthorizeToken(alice, sshOnly, TokenRequest{Template: "tls-client"}); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("no X.509 profile: %v", err)
	}
	// Someone the rules do not name gets nothing.
	if _, err := a.AuthorizeToken(oidcID("mallory@corp.example.com", "visitors"), own, TokenRequest{Template: "user-client"}); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("not in the rules: %v", err)
	}
	// Admins keep what they have.
	if _, err := a.AuthorizeToken(oidcID("carol@corp.example.com", "ca-admins"), own, TokenRequest{Template: "tls-server", Names: []string{"web.example.com"}}); err != nil {
		t.Errorf("admin: %v", err)
	}
}

// Matches tells which rules apply and why, with the test a login uses.
func TestMatches(t *testing.T) {
	a := NewAccess([]Rule{
		{Groups: []string{"devs"}, SSHPrincipals: []string{"deploy"}},
		{Users: []string{"bob@example.com"}, Admin: true},
		{Users: []string{"ALICE@example.com"}, Groups: []string{"ops"}, SSHPrincipals: []string{PlaceholderShortUsername}},
	})
	got := a.Matches(Identity{Username: "alice@example.com", Groups: []string{"Devs", "ops"}})
	want := []Match{{Rule: 0, By: "group Devs"}, {Rule: 2, By: "user"}}
	if !slices.Equal(got, want) {
		t.Errorf("Matches = %v, want %v", got, want)
	}
	if p := a.Principals(Identity{Username: "alice@example.com", Groups: []string{"devs"}}); !slices.Equal(p, []string{"deploy", "alice"}) {
		t.Errorf("Principals = %v, want [deploy alice]", p)
	}
	if m := a.Matches(Identity{Username: "carol@example.com", Groups: []string{"sales"}}); len(m) != 0 {
		t.Errorf("no rule should match carol: %v", m)
	}
}
