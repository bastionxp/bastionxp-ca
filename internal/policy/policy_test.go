// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"net"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
)

// A TLS request may ask only for names in the allowed list: DNS names (case
// does not matter), IP addresses (however written) and email addresses; not
// other names, subdomains, parents, wildcards not listed, or names a listed
// wildcard covers.
func TestCheckX509(t *testing.T) {
	allowed := []string{"web.example.com", "10.0.0.5", "2001:db8::1", "alice@example.com", "*.apps.example.com"}

	tests := []struct {
		name    string
		req     ca.X509Request
		wantErr bool
	}{
		{"one allowed DNS name", ca.X509Request{DNSNames: []string{"web.example.com"}}, false},
		{"upper case is the same name", ca.X509Request{DNSNames: []string{"WEB.Example.com"}}, false},
		{"common name and DNS name", ca.X509Request{CommonName: "web.example.com", DNSNames: []string{"web.example.com"}}, false},
		{"IPv4 address", ca.X509Request{IPAddresses: []net.IP{net.ParseIP("10.0.0.5")}}, false},
		{"IPv6 address written differently", ca.X509Request{IPAddresses: []net.IP{net.ParseIP("2001:0db8:0000:0000:0000:0000:0000:0001")}}, false},
		{"email address", ca.X509Request{EmailAddresses: []string{"alice@example.com"}}, false},
		{"wildcard that is in the list", ca.X509Request{DNSNames: []string{"*.apps.example.com"}}, false},
		{"nothing requested", ca.X509Request{}, false},

		{"other DNS name", ca.X509Request{DNSNames: []string{"db.example.com"}}, true},
		{"one good and one bad DNS name", ca.X509Request{DNSNames: []string{"web.example.com", "db.example.com"}}, true},
		{"bad common name", ca.X509Request{CommonName: "db.example.com", DNSNames: []string{"web.example.com"}}, true},
		{"other IP address", ca.X509Request{IPAddresses: []net.IP{net.ParseIP("10.0.0.6")}}, true},
		{"other email address", ca.X509Request{EmailAddresses: []string{"bob@example.com"}}, true},
		{"subdomain of an allowed name", ca.X509Request{DNSNames: []string{"a.web.example.com"}}, true},
		{"parent of an allowed name", ca.X509Request{DNSNames: []string{"example.com"}}, true},
		{"wildcard that is not in the list", ca.X509Request{DNSNames: []string{"*.example.com"}}, true},
		{"name covered by a wildcard", ca.X509Request{DNSNames: []string{"shop.apps.example.com"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckX509(allowed, tt.req)
			if tt.wantErr && !errors.Is(err, ErrNotAllowed) {
				t.Errorf("error = %v, want ErrNotAllowed", err)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// An empty list of allowed names allows no name at all.
func TestCheckX509WithEmptyListAllowsNothing(t *testing.T) {
	req := ca.X509Request{DNSNames: []string{"web.example.com"}}
	if err := CheckX509(nil, req); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("error = %v, want ErrNotAllowed", err)
	}
}

// An SSH request may ask only for allowed principals, exactly as written:
// not others, not another case, not an empty one.
func TestCheckSSH(t *testing.T) {
	allowed := []string{"alice", "deploy"}

	tests := []struct {
		name       string
		principals []string
		wantErr    bool
	}{
		{"one allowed principal", []string{"alice"}, false},
		{"all allowed principals", []string{"alice", "deploy"}, false},
		{"nothing requested", nil, false},

		{"other principal", []string{"root"}, true},
		{"one good and one bad principal", []string{"alice", "root"}, true},
		{"different upper and lower case", []string{"Alice"}, true},
		{"empty principal", []string{""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckSSH(allowed, tt.principals)
			if tt.wantErr && !errors.Is(err, ErrNotAllowed) {
				t.Errorf("error = %v, want ErrNotAllowed", err)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
