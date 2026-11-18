// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

const day = 24 * time.Hour

// X509Template describes one kind of X.509 certificate the CA issues.
// Use one of the built-in templates below. To change a setting, copy the
// template and modify the copy:
//
//	tmpl := ca.TLSServer
//	tmpl.MaxValidity = 30 * 24 * time.Hour
type X509Template struct {
	Name string
	// Base is the built-in template or base a profile starts from, e.g.
	// "tls-client"; for a built-in template, its own name, except
	// tls-device, which is based on tls-client. Verifiers
	// check it: ACME issues only tls-server-based profiles, for example.
	Base            string
	ExtKeyUsage     []x509.ExtKeyUsage
	DefaultValidity time.Duration // used when the request does not ask for one
	MaxValidity     time.Duration // requests above this are rejected
	// RequireHostName demands at least one DNS name or IP address.
	RequireHostName bool

	// The rest is for profiles (profiles.go); the built-in templates
	// leave it empty.

	// RequireCommonName demands a common name.
	RequireCommonName bool
	// KeyUsage replaces the default: digital signature, plus key
	// encipherment for RSA keys.
	KeyUsage x509.KeyUsage
	// OrganizationalUnit is written into the subject by the CA.
	OrganizationalUnit []string
	// Names limits which kinds of names a certificate may contain. Nil:
	// DNS names, IP addresses and email addresses.
	Names *NamePolicy
	// Policies are certificate policy OIDs (RFC 5280, 4.2.1.4).
	Policies []asn1.ObjectIdentifier
	// Extensions are added to every certificate as they are.
	Extensions []pkix.Extension
	// Keys limits the keys a certificate may be for. Nil: any key the CA
	// accepts.
	Keys *KeyPolicy
}

// TLSServer is for servers: web servers, APIs, databases.
var TLSServer = X509Template{
	Name:            "tls-server",
	Base:            "tls-server",
	ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	DefaultValidity: 24 * time.Hour,
	MaxValidity:     30 * day,
	RequireHostName: true,
}

// TLSClient is for clients that authenticate with mutual TLS: users,
// devices and services.
var TLSClient = X509Template{
	Name:            "tls-client",
	Base:            "tls-client",
	ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	DefaultValidity: 24 * time.Hour,
	MaxValidity:     30 * day,
}

// TLSDevice is a TLS client certificate for managed devices that enroll
// over SCEP. It lives longer than TLSClient because a device renews when
// its device management tells it to, not every few hours. It counts as a
// tls-client profile wherever one is allowed.
var TLSDevice = X509Template{
	Name:            "tls-device",
	Base:            "tls-client",
	ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	DefaultValidity: 30 * day,
	MaxValidity:     90 * day,
}

// X509TemplateByName returns the built-in X.509 template with that name.
func X509TemplateByName(name string) (X509Template, bool) {
	switch name {
	case TLSServer.Name:
		return TLSServer, true
	case TLSClient.Name:
		return TLSClient, true
	case TLSDevice.Name:
		return TLSDevice, true
	}
	return X509Template{}, false
}

// SSHTemplate describes one kind of SSH certificate the CA issues.
type SSHTemplate struct {
	Name string
	// Base is "ssh-user" or "ssh-host": the built-in template a profile
	// starts from, or the template's own name.
	Base            string
	CertType        uint32 // ssh.UserCert or ssh.HostCert
	DefaultValidity time.Duration
	MaxValidity     time.Duration
	// Extensions are copied into the certificate. For user certificates
	// they control what the session may do (terminal, port forwarding...).
	Extensions map[string]string
	// CriticalOptions are copied into the certificate: restrictions the
	// SSH server must enforce, such as "force-command" or
	// "source-address". User certificates only.
	CriticalOptions map[string]string
}

// SSHUser is for people logging in to servers. Short-lived on purpose:
// the user gets a fresh certificate at each login.
var SSHUser = SSHTemplate{
	Name:            "ssh-user",
	Base:            "ssh-user",
	CertType:        ssh.UserCert,
	DefaultValidity: 16 * time.Hour,
	MaxValidity:     24 * time.Hour,
	Extensions: map[string]string{
		"permit-pty":              "",
		"permit-user-rc":          "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding":  "",
		"permit-X11-forwarding":   "",
	},
}

// SSHHost is for SSH servers proving their identity to clients.
var SSHHost = SSHTemplate{
	Name:            "ssh-host",
	Base:            "ssh-host",
	CertType:        ssh.HostCert,
	DefaultValidity: 30 * day,
	MaxValidity:     90 * day,
}

// SSHTemplateByName returns the built-in SSH template with that name.
func SSHTemplateByName(name string) (SSHTemplate, bool) {
	switch name {
	case SSHUser.Name:
		return SSHUser, true
	case SSHHost.Name:
		return SSHHost, true
	}
	return SSHTemplate{}, false
}

// chooseValidity returns the default when nothing was requested and rejects
// requests that are negative or above the maximum.
func chooseValidity(requested, defaultValidity, maxValidity time.Duration) (time.Duration, error) {
	switch {
	case requested == 0:
		return defaultValidity, nil
	case requested < 0:
		return 0, fmt.Errorf("validity must be positive, got %s", requested)
	case requested > maxValidity:
		return 0, fmt.Errorf("validity %s is above the maximum of %s", requested, maxValidity)
	}
	return requested, nil
}
