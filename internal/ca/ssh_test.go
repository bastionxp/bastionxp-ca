// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func newSSHKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, err := ssh.NewPublicKey(newLeafKey(t).Public())
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// checkSSHCert verifies the certificate the way an SSH server or client would.
func checkSSHCert(t *testing.T, authority *CA, cert *ssh.Certificate, trustedCA ssh.PublicKey, principal string) error {
	t.Helper()
	checker := &ssh.CertChecker{
		Clock: authority.now,
		IsUserAuthority: func(key ssh.PublicKey) bool {
			return bytes.Equal(key.Marshal(), trustedCA.Marshal())
		},
		IsHostAuthority: func(key ssh.PublicKey, address string) bool {
			return bytes.Equal(key.Marshal(), trustedCA.Marshal())
		},
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), trustedCA.Marshal()) {
		return errNotTrusted
	}
	return checker.CheckCert(principal, cert)
}

var errNotTrusted = errString("certificate is not signed by the trusted CA")

type errString string

func (e errString) Error() string { return string(e) }

// A user certificate is signed by the user CA key (not the host CA key) and
// accepted for the principals it lists, not for others.
func TestIssueSSHUser(t *testing.T) {
	authority := newTestCA(t)

	cert, err := authority.IssueSSH(SSHRequest{
		Template:   SSHUser,
		PublicKey:  newSSHKey(t),
		KeyID:      "alice@example.com",
		Principals: []string{"alice", "deploy"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if cert.CertType != ssh.UserCert {
		t.Errorf("cert type = %d, want user", cert.CertType)
	}
	if err := checkSSHCert(t, authority, cert, authority.SSHUserCAPublicKey(), "deploy"); err != nil {
		t.Errorf("valid principal rejected: %v", err)
	}
	if err := checkSSHCert(t, authority, cert, authority.SSHUserCAPublicKey(), "root"); err == nil {
		t.Error("certificate accepted for a principal it does not list")
	}
	if err := checkSSHCert(t, authority, cert, authority.SSHHostCAPublicKey(), "alice"); err == nil {
		t.Error("user certificate is signed by the host CA key")
	}
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Error("user certificate is missing the permit-pty extension")
	}
	lifetime := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second
	if lifetime != SSHUser.DefaultValidity+backdate {
		t.Errorf("lifetime = %s, want the template default", lifetime)
	}

	// The certificate must stop working after it expires.
	authority.now = func() time.Time { return time.Now().Add(SSHUser.DefaultValidity + time.Hour) }
	if err := checkSSHCert(t, authority, cert, authority.SSHUserCAPublicKey(), "alice"); err == nil {
		t.Error("expired certificate accepted")
	}
}

// A host certificate is signed by the host CA key, accepted for its host
// name, and has no extensions.
func TestIssueSSHHost(t *testing.T) {
	authority := newTestCA(t)

	cert, err := authority.IssueSSH(SSHRequest{
		Template:   SSHHost,
		PublicKey:  newSSHKey(t),
		KeyID:      "web1.example.com",
		Principals: []string{"web1.example.com"},
		Validity:   24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	if cert.CertType != ssh.HostCert {
		t.Errorf("cert type = %d, want host", cert.CertType)
	}
	if err := checkSSHCert(t, authority, cert, authority.SSHHostCAPublicKey(), "web1.example.com"); err != nil {
		t.Errorf("host certificate rejected: %v", err)
	}
	if len(cert.Extensions) != 0 {
		t.Errorf("host certificate has extensions: %v", cert.Extensions)
	}
}

// Changing an issued certificate's extensions does not change the built-in
// profile.
func TestIssueSSHDoesNotShareTemplateExtensions(t *testing.T) {
	authority := newTestCA(t)
	cert, err := authority.IssueSSH(SSHRequest{
		Template: SSHUser, PublicKey: newSSHKey(t), KeyID: "a", Principals: []string{"a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Changing an issued certificate must not change the built-in template.
	cert.Extensions["test"] = "x"
	if _, ok := SSHUser.Extensions["test"]; ok {
		t.Error("certificate shares its extension map with the template")
	}
}

// Requests the profile does not allow are refused, such as no principals or
// an empty principal.
func TestIssueSSHRejects(t *testing.T) {
	authority := newTestCA(t)
	key := newSSHKey(t)

	tests := []struct {
		name    string
		req     SSHRequest
		wantErr string
	}{
		{
			name:    "no principals",
			req:     SSHRequest{Template: SSHUser, PublicKey: key, KeyID: "a"},
			wantErr: "at least one principal",
		},
		{
			name:    "empty principal",
			req:     SSHRequest{Template: SSHUser, PublicKey: key, KeyID: "a", Principals: []string{""}},
			wantErr: "empty principal",
		},
		{
			name:    "no key ID",
			req:     SSHRequest{Template: SSHUser, PublicKey: key, Principals: []string{"a"}},
			wantErr: "key ID is required",
		},
		{
			name:    "no public key",
			req:     SSHRequest{Template: SSHUser, KeyID: "a", Principals: []string{"a"}},
			wantErr: "no public key",
		},
		{
			name:    "validity above maximum",
			req:     SSHRequest{Template: SSHUser, PublicKey: key, KeyID: "a", Principals: []string{"a"}, Validity: SSHUser.MaxValidity + time.Second},
			wantErr: "above the maximum",
		},
		{
			name:    "no template",
			req:     SSHRequest{PublicKey: key, KeyID: "a", Principals: []string{"a"}},
			wantErr: "no template",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := authority.IssueSSH(tt.req)
			if err == nil {
				t.Fatal("expected an error, got a certificate")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// The SSH profiles are found by name, and a TLS profile is not found as an
// SSH one.
func TestSSHTemplateByName(t *testing.T) {
	for _, want := range []SSHTemplate{SSHUser, SSHHost} {
		got, ok := SSHTemplateByName(want.Name)
		if !ok || got.Name != want.Name {
			t.Errorf("SSHTemplateByName(%q) = %q, %v", want.Name, got.Name, ok)
		}
	}
	if _, ok := SSHTemplateByName("tls-server"); ok {
		t.Error("tls-server must not be found as an SSH template")
	}
}

// A 1024-bit RSA key, and an SSH certificate offered as a key, are refused.
func TestIssueSSHRejectsBadKeys(t *testing.T) {
	authority := newTestCA(t)

	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakKey, err := ssh.NewPublicKey(weakRSA.Public())
	if err != nil {
		t.Fatal(err)
	}

	// An existing certificate, offered as if it were a public key.
	cert, err := authority.IssueSSH(SSHRequest{
		Template: SSHUser, PublicKey: newSSHKey(t), KeyID: "a", Principals: []string{"a"},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		key     ssh.PublicKey
		wantErr string
	}{
		{"weak RSA key", weakKey, "1024 bits"},
		{"certificate instead of key", cert, "is an SSH certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := authority.IssueSSH(SSHRequest{
				Template: SSHUser, PublicKey: tt.key, KeyID: "a", Principals: []string{"a"},
			})
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// Ed25519, RSA 2048 and ECDSA P-256 keys get certificates.
func TestIssueSSHAcceptsCommonKeyTypes(t *testing.T) {
	authority := newTestCA(t)

	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	keys := map[string]crypto.PublicKey{
		"ed25519": ed25519Key.Public(),
		"rsa":     rsaKey.Public(),
		"ecdsa":   ecdsaKey.Public(),
	}
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			pub, err := ssh.NewPublicKey(key)
			if err != nil {
				t.Fatal(err)
			}
			_, err = authority.IssueSSH(SSHRequest{
				Template: SSHUser, PublicKey: pub, KeyID: "a", Principals: []string{"a"},
			})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// A profile's critical options and extensions reach the certificate, and
// the CA finds the profile by name.
func TestIssueSSHProfile(t *testing.T) {
	authority := newTestCA(t)
	ops, _ := SSHProfileBase("ssh-user", "ops-ssh")
	ops.Extensions = map[string]string{"permit-pty": ""}
	ops.CriticalOptions = map[string]string{"source-address": "10.0.0.0/8", "force-command": "/usr/bin/backup"}
	authority.SetProfiles(nil, []SSHTemplate{ops})

	template, ok := authority.SSHTemplate("ops-ssh")
	if !ok {
		t.Fatal("the profile is not found")
	}
	if _, ok := authority.SSHTemplate("ssh-host"); !ok {
		t.Error("the built-in templates are not found next to the profiles")
	}
	cert, err := authority.IssueSSH(SSHRequest{Template: template, PublicKey: newSSHKey(t), KeyID: "alice", Principals: []string{"alice"}})
	if err != nil {
		t.Fatal(err)
	}
	if cert.CriticalOptions["source-address"] != "10.0.0.0/8" || cert.CriticalOptions["force-command"] != "/usr/bin/backup" {
		t.Errorf("critical options %v", cert.CriticalOptions)
	}
	if len(cert.Extensions) != 1 {
		t.Errorf("extensions %v, want only permit-pty", cert.Extensions)
	}
	// The base is not changed by the profile.
	if len(SSHUser.Extensions) != 5 || len(SSHUser.CriticalOptions) != 0 {
		t.Error("the profile changed the built-in template")
	}
}
