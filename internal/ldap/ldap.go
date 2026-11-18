// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package ldap finds out who a person is by checking their username and
// password against a directory: Microsoft Active Directory, or another
// LDAP server such as OpenLDAP. It is the "who are you?" part of the LDAP
// login verifier.
//
// A login takes four steps on one connection:
//
//  1. Bind as the CA's service account.
//  2. Search for the person's entry by the username they typed.
//  3. Bind as that entry with the password they typed. If the directory
//     accepts it, the password is right.
//  4. Bind as the service account again and read the person's groups,
//     nested groups included.
//
// Things that make or break the safety of this:
//
//   - An empty password is refused before the directory is asked. Active
//     Directory treats a bind with a name and an empty password as an
//     anonymous bind and answers "success": without this check, anybody
//     could log in as anybody.
//   - The username is escaped before it goes into the search filter, so a
//     name such as "*" or "a)(objectClass=*" cannot change the search.
//   - Exactly one entry must match; disabled AD accounts are refused.
//   - The connection is always encrypted (LDAPS, or StartTLS), and the
//     directory's certificate is checked.
//   - Failed logins are limited per username and per address, so that the
//     CA cannot be used to lock people out of the directory.
package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/bastionxp/bastionxp-ca/internal/policy"
)

// Errors returned by Login.
var (
	// ErrLoginFailed means the username or password is wrong, or the
	// account may not log in. The person is not told which.
	ErrLoginFailed = errors.New("invalid username or password")
	// ErrTooManyFailures means there were too many failed logins for
	// this username or from this address. Try again later.
	ErrTooManyFailures = errors.New("too many failed logins, try again later")
)

// Defaults for Active Directory.
const (
	DefaultUserFilter        = "(&(objectClass=user)(sAMAccountName={username}))"
	DefaultUsernameAttribute = "userPrincipalName"
	// DefaultGroupFilter finds all groups the person is in, also through
	// other groups. The number is AD's "in chain" matching rule.
	DefaultGroupFilter = "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={user_dn}))"
)

// timeout bounds each connection and each request to the directory.
const timeout = 10 * time.Second

// Config describes the directory.
type Config struct {
	// URL is "ldaps://dc1.corp.example.com", or "ldap://..." with StartTLS.
	URL      string
	StartTLS bool
	// RootCAs checks the directory's certificate. Nil means the roots
	// the operating system trusts.
	RootCAs *x509.CertPool

	// BaseDN is where people are searched, e.g. "DC=corp,DC=example,DC=com".
	BaseDN string
	// BindDN and BindPassword are the CA's service account, used to
	// search. It needs to read people and groups, nothing more.
	BindDN       string
	BindPassword string

	// UserFilter finds the person; "{username}" is replaced by what they
	// typed, escaped.
	UserFilter string
	// UsernameAttribute names the person in the access rules, e.g.
	// "userPrincipalName" (alice@corp.example.com) or "sAMAccountName".
	UsernameAttribute string

	// GroupBaseDN is where groups are searched. Only groups below it
	// count, so a group created elsewhere with a known name cannot hand
	// out rights. Empty means BaseDN.
	GroupBaseDN string
	// GroupFilter finds the person's groups; "{user_dn}" is replaced by
	// their entry's name, escaped.
	GroupFilter string
}

// Client checks logins against the directory. Create one with New. It is
// safe for concurrent use.
type Client struct {
	cfg     Config
	limiter *limiter
}

// New returns a client for the directory. It does not connect yet.
func New(cfg Config) *Client {
	if cfg.GroupBaseDN == "" {
		cfg.GroupBaseDN = cfg.BaseDN
	}
	return &Client{cfg: cfg, limiter: newLimiter()}
}

// Login checks the username and password and returns who the person is:
// their name (from UsernameAttribute, in lower case) and their groups.
// remote is the address the request came from, for the failure limits.
func (c *Client) Login(ctx context.Context, username, password, remote string) (policy.Identity, error) {
	username = strings.TrimSpace(username)
	// Never ask the directory with an empty password: AD would answer
	// "success" for an anonymous bind.
	if username == "" || password == "" {
		return policy.Identity{}, ErrLoginFailed
	}
	if !c.limiter.allow(username, remote) {
		return policy.Identity{}, ErrTooManyFailures
	}

	id, err := c.login(ctx, username, password)
	if errors.Is(err, ErrLoginFailed) {
		c.limiter.failed(username, remote)
	} else if err == nil {
		c.limiter.succeeded(username)
	}
	return id, err
}

func (c *Client) login(ctx context.Context, username, password string) (policy.Identity, error) {
	conn, err := c.connect(ctx)
	if err != nil {
		return policy.Identity{}, err
	}
	defer conn.Close()

	// 1. As the service account.
	if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
		// A mistake in the CA's configuration, not the person's.
		return policy.Identity{}, fmt.Errorf("the directory does not accept the CA's service account: %w", err)
	}

	// 2. Find the person.
	result, err := conn.Search(goldap.NewSearchRequest(
		c.cfg.BaseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		2, int(timeout.Seconds()), false, userFilter(c.cfg.UserFilter, username),
		[]string{c.cfg.UsernameAttribute, "userAccountControl"}, nil))
	if err != nil && !goldap.IsErrorWithCode(err, goldap.LDAPResultSizeLimitExceeded) {
		return policy.Identity{}, fmt.Errorf("cannot search the directory: %w", err)
	}
	// Exactly one: none is an unknown name, two is a filter that does
	// not say who the person is.
	if err != nil || len(result.Entries) != 1 {
		return policy.Identity{}, ErrLoginFailed
	}
	entry := result.Entries[0]
	name := strings.ToLower(strings.TrimSpace(entry.GetEqualFoldAttributeValue(c.cfg.UsernameAttribute)))
	if name == "" {
		return policy.Identity{}, fmt.Errorf("the directory entry of %s has no %s: check ldap.username_attribute", username, c.cfg.UsernameAttribute)
	}
	// AD: bit 2 of userAccountControl is "account disabled".
	if uac := entry.GetEqualFoldAttributeValue("userAccountControl"); uac != "" {
		if flags, err := strconv.ParseUint(uac, 10, 32); err == nil && flags&0x2 != 0 {
			return policy.Identity{}, ErrLoginFailed
		}
	}

	// 3. The password: the directory decides.
	if err := conn.Bind(entry.DN, password); err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultInvalidCredentials) {
			return policy.Identity{}, ErrLoginFailed
		}
		return policy.Identity{}, fmt.Errorf("cannot check the password: %w", err)
	}

	// 4. The groups, as the service account again.
	if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
		return policy.Identity{}, fmt.Errorf("the directory does not accept the CA's service account: %w", err)
	}
	groups, err := c.groups(conn, entry.DN)
	if err != nil {
		return policy.Identity{}, err
	}
	return policy.Identity{Source: "ldap", Username: name, Groups: groups}, nil
}

// groups returns the person's groups below GroupBaseDN, each by its
// common name ("linux-users") and by its full name, so rules can use
// either. The full name is the safer one: common names need not be unique.
func (c *Client) groups(conn *goldap.Conn, userDN string) ([]string, error) {
	result, err := conn.SearchWithPaging(goldap.NewSearchRequest(
		c.cfg.GroupBaseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, int(timeout.Seconds()), false, groupFilter(c.cfg.GroupFilter, userDN), []string{"cn"}, nil), 500)
	if err != nil {
		return nil, fmt.Errorf("cannot read the groups: %w", err)
	}
	var groups []string
	for _, entry := range result.Entries {
		// Only groups below GroupBaseDN, also if the directory's
		// answer says otherwise.
		if !underDN(entry.DN, c.cfg.GroupBaseDN) {
			continue
		}
		if cn := entry.GetEqualFoldAttributeValue("cn"); cn != "" {
			groups = append(groups, cn)
		}
		groups = append(groups, entry.DN)
	}
	return groups, nil
}

// underDN reports whether dn is base or lies below it.
func underDN(dn, base string) bool {
	parsed, err := goldap.ParseDN(dn)
	if err != nil {
		return false
	}
	parsedBase, err := goldap.ParseDN(base)
	if err != nil {
		return false
	}
	return parsedBase.AncestorOfFold(parsed) || parsedBase.EqualFold(parsed)
}

// connect opens an encrypted connection to the directory.
func (c *Client) connect(ctx context.Context) (*goldap.Conn, error) {
	u, err := url.Parse(c.cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid directory address %q", c.cfg.URL)
	}
	tlsConfig := &tls.Config{RootCAs: c.cfg.RootCAs, ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{Timeout: timeout}
	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}
	conn, err := goldap.DialURL(c.cfg.URL, goldap.DialWithDialer(dialer), goldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, fmt.Errorf("cannot reach the directory: %w", err)
	}
	conn.SetTimeout(timeout)
	if c.cfg.StartTLS {
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close()
			return nil, fmt.Errorf("cannot encrypt the connection to the directory: %w", err)
		}
	}
	return conn, nil
}

// Check connects to the directory and binds as the service account, to
// find configuration mistakes before somebody tries to log in.
func (c *Client) Check(ctx context.Context) error {
	conn, err := c.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
		return fmt.Errorf("the directory does not accept the CA's service account: %w", err)
	}
	return nil
}

// userFilter puts what the person typed into the user filter, escaped, so
// that no character of it can change the filter's structure.
func userFilter(template, username string) string {
	return strings.ReplaceAll(template, "{username}", goldap.EscapeFilter(username))
}

// groupFilter puts the person's entry name into the group filter, escaped.
func groupFilter(template, userDN string) string {
	return strings.ReplaceAll(template, "{user_dn}", goldap.EscapeFilter(userDN))
}
