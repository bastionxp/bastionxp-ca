// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ldap_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/ldap"
	"github.com/bastionxp/bastionxp-ca/internal/ldap/ldaptest"
)

const (
	aliceDN = "CN=Alice Smith,OU=People,DC=corp,DC=example,DC=com"
	bobDN   = "CN=Bob,OU=People,DC=corp,DC=example,DC=com"
)

// directory starts a fake AD with two people and some groups:
//
//	linux-users  <- alice
//	ssh-admins   <- linux-admins <- alice   (nested)
//	ca-admins    outside the groups OU      (must not count)
func directory(t *testing.T) *ldaptest.Fake {
	t.Helper()
	fake := ldaptest.NewFake()
	t.Cleanup(fake.Close)
	fake.AddUser(ldaptest.User{DN: aliceDN, SAM: "alice", UPN: "Alice@Corp.Example.com", Password: "alice-pw"})
	fake.AddUser(ldaptest.User{DN: bobDN, SAM: "bob", UPN: "bob@corp.example.com", Password: "bob-pw", Disabled: true})
	fake.AddGroup(ldaptest.Group{DN: "CN=linux-users,OU=Groups,DC=corp,DC=example,DC=com", Members: []string{aliceDN}})
	fake.AddGroup(ldaptest.Group{DN: "CN=linux-admins,OU=Groups,DC=corp,DC=example,DC=com", Members: []string{aliceDN}})
	fake.AddGroup(ldaptest.Group{DN: "CN=ssh-admins,OU=Groups,DC=corp,DC=example,DC=com",
		Members: []string{"CN=linux-admins,OU=Groups,DC=corp,DC=example,DC=com"}})
	fake.AddGroup(ldaptest.Group{DN: "CN=ca-admins,OU=Elsewhere,DC=corp,DC=example,DC=com", Members: []string{aliceDN}})
	return fake
}

func configFor(fake *ldaptest.Fake) ldap.Config {
	return ldap.Config{
		URL:               fake.URL(),
		RootCAs:           fake.RootCAs(),
		BaseDN:            ldaptest.BaseDN,
		BindDN:            ldaptest.ServiceDN,
		BindPassword:      ldaptest.ServicePassword,
		UserFilter:        ldap.DefaultUserFilter,
		UsernameAttribute: ldap.DefaultUsernameAttribute,
		GroupBaseDN:       ldaptest.GroupBaseDN,
		GroupFilter:       ldap.DefaultGroupFilter,
	}
}

// An LDAP login returns the user's principal name and groups, nested groups
// included, by name and DN; groups outside the group base DN do not count.
func TestLogin(t *testing.T) {
	fake := directory(t)
	id, err := ldap.New(configFor(fake)).Login(context.Background(), "alice", "alice-pw", "10.0.0.5:5000")
	if err != nil {
		t.Fatal(err)
	}
	if id.Source != "ldap" || id.Username != "alice@corp.example.com" {
		t.Errorf("identity = %+v, want alice@corp.example.com from ldap", id)
	}
	for _, want := range []string{"linux-users", "linux-admins", "ssh-admins", "CN=linux-users,OU=Groups,DC=corp,DC=example,DC=com"} {
		if !slices.Contains(id.Groups, want) {
			t.Errorf("groups = %v, want %s among them", id.Groups, want)
		}
	}
	if slices.Contains(id.Groups, "ca-admins") {
		t.Errorf("groups = %v: ca-admins is outside group_base_dn and must not count", id.Groups)
	}
}

// An LDAP login over StartTLS.
func TestLoginWithStartTLS(t *testing.T) {
	fake := ldaptest.NewStartTLSFake()
	t.Cleanup(fake.Close)
	fake.AddUser(ldaptest.User{DN: aliceDN, SAM: "alice", UPN: "alice@corp.example.com", Password: "alice-pw"})
	cfg := configFor(fake)
	cfg.StartTLS = true
	if _, err := ldap.New(cfg).Login(context.Background(), "alice", "alice-pw", "10.0.0.5:5000"); err != nil {
		t.Fatal(err)
	}
}

// A wrong password fails the login.
func TestWrongPassword(t *testing.T) {
	fake := directory(t)
	_, err := ldap.New(configFor(fake)).Login(context.Background(), "alice", "wrong", "10.0.0.5:5000")
	if !errors.Is(err, ldap.ErrLoginFailed) {
		t.Errorf("error = %v, want ErrLoginFailed", err)
	}
}

// AD takes a name with an empty password as an anonymous login and says
// "success". The client must not even ask.
func TestEmptyPasswordIsNeverSent(t *testing.T) {
	fake := directory(t)
	client := ldap.New(configFor(fake))
	for _, name := range []string{"alice", aliceDN, "", "  "} {
		_, err := client.Login(context.Background(), name, "", "10.0.0.5:5000")
		if !errors.Is(err, ldap.ErrLoginFailed) {
			t.Errorf("error = %v, want ErrLoginFailed", err)
		}
	}
	if binds := fake.Binds(); len(binds) != 0 {
		t.Errorf("binds = %+v, want none", binds)
	}
}

// An unknown user fails the login, like a wrong password.
func TestUnknownUser(t *testing.T) {
	fake := directory(t)
	_, err := ldap.New(configFor(fake)).Login(context.Background(), "mallory", "pw", "10.0.0.5:5000")
	if !errors.Is(err, ldap.ErrLoginFailed) {
		t.Errorf("error = %v, want ErrLoginFailed", err)
	}
}

// A disabled account fails the login without its password being tried.
func TestDisabledAccount(t *testing.T) {
	fake := directory(t)
	_, err := ldap.New(configFor(fake)).Login(context.Background(), "bob", "bob-pw", "10.0.0.5:5000")
	if !errors.Is(err, ldap.ErrLoginFailed) {
		t.Errorf("error = %v, want ErrLoginFailed", err)
	}
	for _, bind := range fake.Binds() {
		if bind.DN == bobDN {
			t.Error("the password of a disabled account was tried")
		}
	}
}

// A filter that matches more than one person does not say who logs in.
func TestAmbiguousMatch(t *testing.T) {
	fake := directory(t)
	cfg := configFor(fake)
	cfg.UserFilter = "(|(sAMAccountName={username})(objectClass=user))"
	_, err := ldap.New(cfg).Login(context.Background(), "alice", "alice-pw", "10.0.0.5:5000")
	if !errors.Is(err, ldap.ErrLoginFailed) {
		t.Errorf("error = %v, want ErrLoginFailed", err)
	}
}

// Special characters in the username must not change the search.
func TestFilterInjection(t *testing.T) {
	fake := directory(t)
	client := ldap.New(configFor(fake))
	for _, name := range []string{"*", "a*", "alice)(objectClass=*", "*)(|(sAMAccountName=*"} {
		_, err := client.Login(context.Background(), name, "alice-pw", "10.0.0.5:5000")
		if !errors.Is(err, ldap.ErrLoginFailed) {
			t.Errorf("%q: error = %v, want ErrLoginFailed", name, err)
		}
	}
	for _, filter := range fake.Filters() {
		if strings.Contains(filter, "sAMAccountName=*") || strings.Contains(filter, "(objectClass=*)") {
			t.Errorf("filter %q was changed by the username", filter)
		}
	}
	for _, bind := range fake.Binds() {
		if bind.DN == aliceDN {
			t.Error("a crafted name reached alice's entry")
		}
	}
}

// After repeated failures for a name, in any case, even the right password
// is not passed to the directory, so it does not lock the account; other
// names are not affected.
func TestTooManyFailures(t *testing.T) {
	fake := directory(t)
	client := ldap.New(configFor(fake))
	for range 3 {
		if _, err := client.Login(context.Background(), "alice", "wrong", "10.0.0.5:5000"); !errors.Is(err, ldap.ErrLoginFailed) {
			t.Fatalf("error = %v, want ErrLoginFailed", err)
		}
	}
	before := len(fake.Binds())
	// Now even the right password is not passed on, so that the
	// directory does not lock the account.
	_, err := client.Login(context.Background(), "Alice", "alice-pw", "10.0.0.6:5000")
	if !errors.Is(err, ldap.ErrTooManyFailures) {
		t.Errorf("error = %v, want ErrTooManyFailures", err)
	}
	if len(fake.Binds()) != before {
		t.Error("the directory was asked although the limit was reached")
	}
	// Others are not affected.
	if _, err := client.Login(context.Background(), "nobody", "pw", "10.0.0.7:5000"); !errors.Is(err, ldap.ErrLoginFailed) {
		t.Errorf("error = %v, want ErrLoginFailed for another name", err)
	}
}

// Many failures from one address block further logins from it, not from
// other addresses.
func TestTooManyFailuresFromOneAddress(t *testing.T) {
	fake := directory(t)
	client := ldap.New(configFor(fake))
	for i := range 20 {
		_, _ = client.Login(context.Background(), "user"+string(rune('a'+i)), "pw", "10.0.0.5:5000")
	}
	_, err := client.Login(context.Background(), "alice", "alice-pw", "10.0.0.5:6000")
	if !errors.Is(err, ldap.ErrTooManyFailures) {
		t.Errorf("error = %v, want ErrTooManyFailures", err)
	}
	if _, err := client.Login(context.Background(), "alice", "alice-pw", "10.0.0.9:6000"); err != nil {
		t.Errorf("another address: %v", err)
	}
}

// A wrong service account is the CA's mistake: it must not look like the
// person's wrong password, nor count against them.
func TestWrongServicePassword(t *testing.T) {
	fake := directory(t)
	cfg := configFor(fake)
	cfg.BindPassword = "wrong"
	client := ldap.New(cfg)
	for range 5 {
		_, err := client.Login(context.Background(), "alice", "alice-pw", "10.0.0.5:5000")
		if err == nil || errors.Is(err, ldap.ErrLoginFailed) || errors.Is(err, ldap.ErrTooManyFailures) {
			t.Fatalf("error = %v, want a configuration error", err)
		}
	}
}

// A directory that cannot be reached is a connection error, not a failed
// login.
func TestDirectoryDown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	cfg := configFor(directory(t))
	cfg.URL = "ldaps://" + addr
	_, err = ldap.New(cfg).Login(context.Background(), "alice", "alice-pw", "10.0.0.5:5000")
	if err == nil || errors.Is(err, ldap.ErrLoginFailed) {
		t.Errorf("error = %v, want a connection error", err)
	}
}

// The directory's certificate is checked: the password must not go to an
// impostor.
func TestUnknownCertificate(t *testing.T) {
	fake := directory(t)
	cfg := configFor(fake)
	cfg.RootCAs = x509.NewCertPool()
	_, err := ldap.New(cfg).Login(context.Background(), "alice", "alice-pw", "10.0.0.5:5000")
	if err == nil || errors.Is(err, ldap.ErrLoginFailed) {
		t.Errorf("error = %v, want a certificate error", err)
	}
	if len(fake.Binds()) != 0 {
		t.Error("credentials were sent to a directory with an unknown certificate")
	}
}

// sAMAccountName can be the username instead of the principal name.
func TestSAMAccountNameAsUsername(t *testing.T) {
	fake := directory(t)
	cfg := configFor(fake)
	cfg.UsernameAttribute = "sAMAccountName"
	id, err := ldap.New(cfg).Login(context.Background(), "alice", "alice-pw", "10.0.0.5:5000")
	if err != nil {
		t.Fatal(err)
	}
	if id.Username != "alice" {
		t.Errorf("username = %q, want alice", id.Username)
	}
}
