// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"slices"
	"strings"
)

// Identity is a person who logged in: who they are, and the groups the
// identity provider says they are in.
type Identity struct {
	// Source is how they logged in, e.g. "oidc".
	Source string
	// Username is their name at that source, e.g.
	// "alice@corp.example.com".
	Username string
	// Groups are the groups the identity provider reports.
	Groups []string
}

// Rule gives the people it matches the right to certain certificates.
// A person matches if their name is in Users or one of their groups is
// in Groups.
type Rule struct {
	Users  []string
	Groups []string
	// SSHPrincipals are the login names on servers the people may get
	// SSH user certificates for, themselves. "{username}" stands for
	// the person's name and "{short_username}" for the part of it
	// before an "@".
	SSHPrincipals []string
	// Admin lets the people get a one-time token for any certificate,
	// for anybody.
	Admin bool
}

// Placeholders that may appear in SSHPrincipals.
const (
	PlaceholderUsername      = "{username}"
	PlaceholderShortUsername = "{short_username}"
)

// Access decides what logged-in people may have, from a list of rules.
// Create one with NewAccess. It is safe for concurrent use, and never
// changes: to change the rules, make a new one.
//
// Names and groups ignore upper and lower case: email addresses, AD names
// and Entra group IDs all do.
type Access struct {
	rules []Rule
}

// NewAccess returns the rules as a policy.
func NewAccess(rules []Rule) *Access {
	return &Access{rules: slices.Clone(rules)}
}

// matches reports whether a rule applies to a person.
func (r *Rule) matches(id Identity) bool {
	if containsFold(r.Users, id.Username) {
		return true
	}
	for _, group := range id.Groups {
		if containsFold(r.Groups, group) {
			return true
		}
	}
	return false
}

// Match is a rule that applies to a person, and why.
type Match struct {
	// Rule is the rule's place in the list, from 0.
	Rule int
	// By says why it applies: "user", or "group <name>".
	By string
}

// Matches returns the rules that apply to a person, in their order. It is
// for "bxp access check": a login uses the same test.
func (a *Access) Matches(id Identity) []Match {
	var out []Match
	for i := range a.rules {
		r := &a.rules[i]
		switch {
		case containsFold(r.Users, id.Username):
			out = append(out, Match{Rule: i, By: "user"})
		default:
			for _, group := range id.Groups {
				if containsFold(r.Groups, group) {
					out = append(out, Match{Rule: i, By: "group " + group})
					break
				}
			}
		}
	}
	return out
}

// Principals returns the SSH principals a person may have for themselves,
// in the order the rules give them, each once.
func (a *Access) Principals(id Identity) []string { return a.principals(id) }

func containsFold(list []string, s string) bool {
	for _, item := range list {
		if strings.EqualFold(item, s) {
			return true
		}
	}
	return false
}

// principals returns the SSH principals a person may have for themselves,
// in the order the rules give them, each once.
func (a *Access) principals(id Identity) []string {
	short, _, _ := strings.Cut(id.Username, "@")
	var out []string
	for i := range a.rules {
		if !a.rules[i].matches(id) {
			continue
		}
		for _, p := range a.rules[i].SSHPrincipals {
			p = strings.ReplaceAll(p, PlaceholderUsername, id.Username)
			p = strings.ReplaceAll(p, PlaceholderShortUsername, short)
			if p != "" && !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out
}

// IsAdmin reports whether the person may get tokens for anybody.
func (a *Access) IsAdmin(id Identity) bool {
	if id.Username == "" {
		return false
	}
	for i := range a.rules {
		if a.rules[i].Admin && a.rules[i].matches(id) {
			return true
		}
	}
	return false
}

// MayLogIn reports whether the person may get anything at all.
func (a *Access) MayLogIn(id Identity) bool {
	return id.Username != "" && (a.IsAdmin(id) || len(a.principals(id)) > 0)
}

// TokenRequest describes the one-time token a logged-in person asks for.
type TokenRequest struct {
	Template string
	Names    []string
	// Subject is who the token is for. Empty means "decide for me".
	Subject string
}

// Own is what a verifier gives the people who log in through it, for
// themselves: the profiles of their SSH user certificate and of their TLS
// client certificate (oidc.ssh / oidc.x509 in the configuration, and the
// same for ldap).
type Own struct {
	SSHProfile  string
	X509Profile string
}

// AuthorizeToken decides whether the person may have the token they ask
// for. It returns the request as it should be issued, or ErrNotAllowed.
//
// Two requests are "for themselves", and every person the rules let log
// in may make them:
//
//   - an SSH certificate of own.SSHProfile with their own principals
//     (asking for no names means all of them);
//   - a TLS certificate of own.X509Profile for their own name, and no
//     other (asking for no names means that one).
//
// The subject is then set to their name, so the certificate always
// carries the name of the person who logged in. Everything else needs an
// admin.
func (a *Access) AuthorizeToken(id Identity, own Own, req TokenRequest) (TokenRequest, error) {
	principals := a.principals(id)
	subjectIsThem := req.Subject == "" || strings.EqualFold(req.Subject, id.Username)

	if id.Username != "" && subjectIsThem && req.Template == own.SSHProfile &&
		len(principals) > 0 && CheckSSH(principals, req.Names) == nil {
		if len(req.Names) == 0 {
			req.Names = principals
		}
		req.Subject = id.Username
		return req, nil
	}
	if id.Username != "" && subjectIsThem && own.X509Profile != "" && req.Template == own.X509Profile &&
		a.MayLogIn(id) && (len(req.Names) == 0 || (len(req.Names) == 1 && strings.EqualFold(req.Names[0], id.Username))) {
		req.Names = []string{id.Username}
		req.Subject = id.Username
		return req, nil
	}

	if a.IsAdmin(id) {
		return req, nil
	}

	if !a.MayLogIn(id) {
		return TokenRequest{}, fmt.Errorf("%w: %s may not request certificates", ErrNotAllowed, id.Username)
	}
	var may []string
	if len(principals) > 0 {
		may = append(may, fmt.Sprintf("%s certificates with these principals: %s", own.SSHProfile, strings.Join(principals, ", ")))
	}
	if own.X509Profile != "" {
		may = append(may, fmt.Sprintf("a %s certificate for %s", own.X509Profile, id.Username))
	}
	return TokenRequest{}, fmt.Errorf("%w: %s may only request, for themselves, %s",
		ErrNotAllowed, id.Username, strings.Join(may, "; or "))
}
