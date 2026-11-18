// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package policy answers one question: may this requester have these names?
//
// A verifier works out which names a requester is allowed to have (a token
// lists them, for example). This package compares that list with what the
// certificate request asks for. The CA only signs after this check passed.
package policy

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
)

// ErrNotAllowed is returned when a request asks for a name the requester
// may not have.
var ErrNotAllowed = errors.New("not allowed")

// CheckX509 returns ErrNotAllowed if the request contains a common name,
// DNS name, IP address or email address that is not in the allowed list.
//
// Names must match exactly, ignoring upper and lower case. A wildcard such
// as "*.example.com" is only allowed if the list contains that same text.
func CheckX509(allowed []string, req ca.X509Request) error {
	allowedSet := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		allowedSet[normalize(name)] = true
	}

	var requested []string
	if req.CommonName != "" {
		requested = append(requested, req.CommonName)
	}
	requested = append(requested, req.DNSNames...)
	requested = append(requested, req.EmailAddresses...)
	for _, ip := range req.IPAddresses {
		requested = append(requested, ip.String())
	}

	for _, name := range requested {
		if !allowedSet[normalize(name)] {
			return fmt.Errorf("%w: the name %q", ErrNotAllowed, name)
		}
	}
	return nil
}

// CheckSSH returns ErrNotAllowed if one of the requested principals is not
// in the allowed list.
//
// Principals must match exactly, including upper and lower case, because
// login names on a server are case sensitive: "Root" is not "root".
func CheckSSH(allowed []string, principals []string) error {
	allowedSet := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = true
	}
	for _, principal := range principals {
		if !allowedSet[principal] {
			return fmt.Errorf("%w: the principal %q", ErrNotAllowed, principal)
		}
	}
	return nil
}

// normalize makes two spellings of the same name compare as equal:
// "Web.Example.COM" and "web.example.com", or two ways of writing the
// same IP address.
func normalize(name string) string {
	if ip := net.ParseIP(name); ip != nil {
		return ip.String()
	}
	return strings.ToLower(name)
}
