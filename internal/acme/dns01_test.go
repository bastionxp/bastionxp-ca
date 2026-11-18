// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"net"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// startDNS starts a DNS server on UDP that knows the given TXT records and
// answers "no such name" for anything else.
func startDNS(t *testing.T, records map[string][]string) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if err := query.Unpack(buf[:n]); err != nil || len(query.Questions) != 1 {
				continue
			}
			q := query.Questions[0]
			answer := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true, RCode: dnsmessage.RCodeNameError},
				Questions: query.Questions,
			}
			if values, ok := records[q.Name.String()]; ok {
				answer.RCode = dnsmessage.RCodeSuccess
				if q.Type == dnsmessage.TypeTXT {
					answer.Answers = []dnsmessage.Resource{{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60},
						Body:   &dnsmessage.TXTResource{TXT: values},
					}}
				}
			}
			packed, err := answer.Pack()
			if err == nil {
				conn.WriteTo(packed, from)
			}
		}
	}()
	return conn.LocalAddr().String()
}

// acme.dns_resolver: the lookup goes to that server, not to the
// machine's resolvers.
func TestDirectResolver(t *testing.T) {
	address := startDNS(t, map[string][]string{"_acme-challenge.web.example.com.": {"the-value"}})
	resolver := directResolver(address)
	got, err := resolver.LookupTXT(context.Background(), "_acme-challenge.web.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"the-value"}) {
		t.Errorf("TXT = %v", got)
	}
	if _, err := resolver.LookupTXT(context.Background(), "_acme-challenge.other.example.com."); err == nil {
		t.Error("a name the server does not know was found")
	}
}

// The whole dns-01 road through a real DNS server.
func TestDNS01WithDNSServer(t *testing.T) {
	env := newTestEnv(t)
	client := env.registered()
	order, authzs := env.order(client, "web.example.com")
	challenge := challengeOfType(t, authzs[0], "dns-01")
	record, err := client.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		t.Fatal(err)
	}
	env.server.lookupTXT = directResolver(startDNS(t, map[string][]string{
		"_acme-challenge.web.example.com.": {record},
	})).LookupTXT
	ctx := context.Background()
	if _, err := client.Accept(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WaitAuthorization(ctx, authzs[0].URI); err != nil {
		t.Fatal(err)
	}
	env.finish(client, order, "web.example.com")
}
