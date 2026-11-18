// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ldap

import (
	"testing"
	"unicode/utf8"

	goldap "github.com/go-ldap/ldap/v3"
)

// FuzzUserFilter checks that no username can change the search: the
// filter always compiles to the same shape, with the username, unchanged,
// as the value of the one equality test.
func FuzzUserFilter(f *testing.F) {
	for _, seed := range []string{"alice", "*", "a)(objectClass=*", `\2a`, "\x00", "*)(|(sAMAccountName=*", "äöü", ")"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, username string) {
		if !utf8.ValidString(username) {
			return // a username comes from JSON: valid UTF-8
		}
		packet, err := goldap.CompileFilter(userFilter(DefaultUserFilter, username))
		if err != nil {
			t.Fatalf("username %q breaks the filter: %v", username, err)
		}
		// (&(objectClass=user)(sAMAccountName=<username>))
		if packet.Tag != goldap.FilterAnd || len(packet.Children) != 2 {
			t.Fatalf("username %q changed the filter's shape", username)
		}
		for i, wantAttr := range []string{"objectClass", "sAMAccountName"} {
			eq := packet.Children[i]
			if eq.Tag != goldap.FilterEqualityMatch || len(eq.Children) != 2 {
				t.Fatalf("username %q: part %d is not an equality test", username, i)
			}
			if attr := eq.Children[0].Data.String(); attr != wantAttr {
				t.Fatalf("username %q: attribute %q, want %q", username, attr, wantAttr)
			}
		}
		if got := string(packet.Children[1].Children[1].Data.Bytes()); got != username {
			t.Fatalf("searched for %q, want exactly %q", got, username)
		}
	})
}

// FuzzGroupFilter checks that the DN of the person's entry, which comes
// from the directory, cannot change the group search: the filter always
// has the same shape, with the DN, unchanged, as the in-chain match.
func FuzzGroupFilter(f *testing.F) {
	for _, seed := range []string{"CN=Alice,DC=corp", "CN=a)(cn=*", `CN=x\,y,DC=z`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, dn string) {
		if !utf8.ValidString(dn) {
			return
		}
		packet, err := goldap.CompileFilter(groupFilter(DefaultGroupFilter, dn))
		if err != nil {
			t.Fatalf("DN %q breaks the filter: %v", dn, err)
		}
		if packet.Tag != goldap.FilterAnd || len(packet.Children) != 2 {
			t.Fatalf("DN %q changed the filter's shape", dn)
		}
		ext := packet.Children[1]
		if ext.Tag != goldap.FilterExtensibleMatch {
			t.Fatalf("DN %q: second part is not the in-chain match", dn)
		}
		for _, child := range ext.Children {
			if child.Tag == 3 && string(child.Data.Bytes()) != dn {
				t.Fatalf("matched %q, want exactly %q", child.Data.Bytes(), dn)
			}
		}
	})
}
