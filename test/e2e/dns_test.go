// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && !windows

package e2e

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"strings"
	"testing"
)

// fakeDNS is a DNS server for dns-01: it answers TXT questions from a
// file of "name value" lines, which an ACME client's hook writes, and
// every other question with an empty answer. Only what dns-01 needs, over
// UDP.
type fakeDNS struct {
	addr    string // 127.0.0.1:<port>
	records string // the file of "name value" lines
}

func startFakeDNS(t *testing.T) *fakeDNS {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDNS{addr: conn.LocalAddr().String(), records: t.TempDir() + "/records"}
	writeFile(t, d.records, "")
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if answer := d.answer(buf[:n]); answer != nil {
				conn.WriteTo(answer, from)
			}
		}
	}()
	return d
}

// txt returns the TXT values for a name, from the records file.
func (d *fakeDNS) txt(name string) []string {
	data, _ := os.ReadFile(d.records)
	var values []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.EqualFold(strings.TrimSuffix(fields[0], "."), strings.TrimSuffix(name, ".")) {
			values = append(values, fields[1])
		}
	}
	return values
}

// answer builds the response to one query (RFC 1035, section 4).
func (d *fakeDNS) answer(query []byte) []byte {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil
	}
	// The question: the name's labels, then type and class.
	name, i := []string{}, 12
	for i < len(query) && query[i] != 0 {
		l := int(query[i])
		if i+1+l > len(query) {
			return nil
		}
		name = append(name, string(query[i+1:i+1+l]))
		i += 1 + l
	}
	if i+5 > len(query) {
		return nil
	}
	questionEnd := i + 5
	qtype := binary.BigEndian.Uint16(query[i+1 : i+3])

	var answers [][]byte
	if qtype == 16 { // TXT
		for _, value := range d.txt(strings.Join(name, ".")) {
			rdata := append([]byte{byte(len(value))}, value...)
			rr := []byte{0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 0} // name: the question's; TXT; IN; TTL 0
			rr = binary.BigEndian.AppendUint16(rr, uint16(len(rdata)))
			answers = append(answers, append(rr, rdata...))
		}
	}
	resp := make([]byte, 12, 512)
	copy(resp, query[:2])                                       // ID
	resp[2] = 0x84 | query[2]&0x01                              // response, authoritative, RD as asked
	resp[3] = 0                                                 // no error
	binary.BigEndian.PutUint16(resp[4:6], 1)                    // one question
	binary.BigEndian.PutUint16(resp[6:8], uint16(len(answers))) // answers
	resp = append(resp, query[12:questionEnd]...)
	for _, a := range answers {
		resp = append(resp, a...)
	}
	return resp
}

// TestFakeDNS checks the fake against Go's resolver, so that a failure
// of the dns-01 test is not the fake's fault.
func TestFakeDNS(t *testing.T) {
	d := startFakeDNS(t)
	writeFile(t, d.records, "_acme-challenge.x.e2e.localhost. abc123\n")
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "udp", d.addr)
	}}
	got, err := resolver.LookupTXT(t.Context(), "_acme-challenge.x.e2e.localhost")
	if err != nil || len(got) != 1 || got[0] != "abc123" {
		t.Fatalf("LookupTXT = %v, %v", got, err)
	}
}
