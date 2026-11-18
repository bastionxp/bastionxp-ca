// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// withAgent gives the connection an in-memory ssh-agent.
func withAgent(conn connection) (connection, agent.Agent) {
	keyring := agent.NewKeyring()
	conn.agentDial = func() (net.Conn, error) {
		client, server := net.Pipe()
		go agent.ServeAgent(keyring, server)
		return client, nil
	}
	return conn, keyring
}

// agentCert returns the one certificate in the agent.
func agentCert(t *testing.T, keyring agent.Agent) *ssh.Certificate {
	t.Helper()
	keys, err := keyring.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if pub, err := ssh.ParsePublicKey(k.Blob); err == nil {
			if cert, ok := pub.(*ssh.Certificate); ok {
				return cert
			}
		}
	}
	t.Fatalf("no certificate in the agent (%d keys)", len(keys))
	return nil
}

// --agent without --key: a new key in memory, nothing on disk.
func TestSSHAgentOnly(t *testing.T) {
	testCA := startTestCA(t)
	conn, keyring := withAgent(testCA.connection(t, "ssh-user", "alice"))
	dir := t.TempDir()
	t.Chdir(dir)

	var out bytes.Buffer
	if err := runSSH(context.Background(), &out, conn, sshOptions{agent: true}); err != nil {
		t.Fatal(err)
	}
	cert := agentCert(t, keyring)
	if strings.Join(cert.ValidPrincipals, ",") != "alice" || cert.CertType != ssh.UserCert {
		t.Errorf("certificate: principals %v, type %d", cert.ValidPrincipals, cert.CertType)
	}
	// The agent can sign with it: the private key is there too.
	signers, err := keyring.Signers()
	if err != nil || len(signers) == 0 {
		t.Fatalf("signers: %d, %v", len(signers), err)
	}
	if _, err := signers[0].Sign(rand.Reader, []byte("data")); err != nil {
		t.Error(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("files written: %v", entries)
	}
	if !strings.Contains(out.String(), "ssh-agent") {
		t.Errorf("output:\n%s", out.String())
	}
}

// --agent with --key: the certificate file as always, and the key with
// its certificate in the agent.
func TestSSHAgentWithKey(t *testing.T) {
	testCA := startTestCA(t)
	conn, keyring := withAgent(testCA.connection(t, "ssh-user", "alice"))
	dir := t.TempDir()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "id_ed25519")
	os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600)
	sshPub, _ := ssh.NewPublicKey(private.Public())
	os.WriteFile(keyFile+".pub", ssh.MarshalAuthorizedKey(sshPub), 0o644)

	if err := runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: keyFile + ".pub", agent: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keyFile + "-cert.pub"); err != nil {
		t.Error("no certificate file")
	}
	if cert := agentCert(t, keyring); !bytes.Equal(cert.Key.Marshal(), sshPub.Marshal()) {
		t.Error("the agent has the certificate of another key")
	}
}

// A key with a passphrase and no terminal: it says so, before a token is
// spent.
func TestSSHAgentKeyWithPassphrase(t *testing.T) {
	testCA := startTestCA(t)
	conn, _ := withAgent(testCA.connection(t, "ssh-user", "alice"))
	dir := t.TempDir()
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "id_ed25519")
	os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600)
	sshPub, _ := ssh.NewPublicKey(private.Public())
	os.WriteFile(keyFile+".pub", ssh.MarshalAuthorizedKey(sshPub), 0o644)

	err = runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: keyFile + ".pub", agent: true})
	if err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("error = %v, want one about the passphrase", err)
	}
	// The token was not used: it still works.
	conn.agentDial = nil
	if err := runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: keyFile + ".pub"}); err != nil {
		t.Errorf("the token was spent: %v", err)
	}
}

// bxp ssh --agent without a running agent says how to start one
// (SSH_AUTH_SOCK), and bxp ssh with neither --key nor --agent says what is
// missing.
func TestSSHAgentMissing(t *testing.T) {
	testCA := startTestCA(t)
	t.Setenv("SSH_AUTH_SOCK", "")
	conn := testCA.connection(t, "ssh-user", "alice")
	err := runSSH(context.Background(), io.Discard, conn, sshOptions{agent: true})
	if err == nil || !strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
		t.Errorf("error = %v, want a hint about SSH_AUTH_SOCK", err)
	}
	if err := runSSH(context.Background(), io.Discard, conn, sshOptions{}); err == nil || !strings.Contains(err.Error(), "--agent") {
		t.Errorf("neither --key nor --agent: %v", err)
	}
}
