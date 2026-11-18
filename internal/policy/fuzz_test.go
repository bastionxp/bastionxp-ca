// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"strings"
	"testing"
)

// FuzzCheckDomain checks that every name the ACME policy accepts lies
// inside an allowed domain, whatever the fuzzer tries.
func FuzzCheckDomain(f *testing.F) {
	for _, seed := range []string{"web.example.com", "*.example.com", "example.com.evil.net", "badexample.com",
		"*.*.example.com", "web.example.com.", "WEB.EXAMPLE.COM", "xn--bcher-kva.example.com", "10.0.0.1", "*"} {
		f.Add(seed)
	}
	a := NewACME([]string{"example.com", "corp.internal"})
	f.Fuzz(func(t *testing.T, name string) {
		if a.CheckDomain(name) != nil {
			return
		}
		base := strings.TrimPrefix(strings.ToLower(name), "*.")
		inside := false
		for _, domain := range []string{"example.com", "corp.internal"} {
			if base == domain || strings.HasSuffix(base, "."+domain) {
				inside = true
			}
		}
		if !inside {
			t.Fatalf("accepted %q, which is outside the allowed domains", name)
		}
		if strings.ContainsAny(base, "* /:@\\\x00") || strings.HasSuffix(base, ".") {
			t.Fatalf("accepted %q, which is not a host name", name)
		}
	})
}
