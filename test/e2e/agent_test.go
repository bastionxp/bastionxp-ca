// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && !windows

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// "bxp ssh --agent" with a real ssh-agent: without --key, a new key and its
// certificate go into the agent and nothing touches the disk; with --key,
// the certificate file is written and the agent holds both.
func TestSSHAgent(t *testing.T) {
	sshAgent, sshAdd, sshKeygen := tool(t, "ssh-agent"), tool(t, "ssh-add"), tool(t, "ssh-keygen")
	c := newCA(t, "")
	c.start()
	c.trust()

	// A socket path short enough for Unix sockets (about 100 bytes).
	sockDir, err := os.MkdirTemp("/tmp", "bxp-agent-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "agent.sock")
	background(t, sshAgent, "-D", "-a", sock)
	waitForSocket(t, sock)
	agentEnv := append(append([]string{}, c.env...), "SSH_AUTH_SOCK="+sock)
	listAgent := func() string {
		t.Helper()
		return run(t, c.dir, agentEnv, sshAdd, "-L").stdout
	}

	// No key: made in memory, into the agent, nowhere else.
	work := t.TempDir()
	r := run(t, work, agentEnv, bxpBin, "ssh", "--agent", "--token", c.token("ssh-user", "deploy"))
	if r.code != 0 {
		t.Fatalf("bxp ssh --agent:\n%s", r)
	}
	if !strings.Contains(listAgent(), "-cert-v01@openssh.com") {
		t.Fatalf("no certificate in the agent:\n%s", listAgent())
	}
	if entries, _ := os.ReadDir(work); len(entries) != 0 {
		t.Errorf("bxp ssh --agent without --key wrote files: %v", entries)
	}
	if _, err := os.Stat(filepath.Join(c.dir, "home", ".ssh")); err == nil {
		t.Error("bxp ssh --agent without --key wrote to ~/.ssh")
	}

	// With --key: the file too, and the agent holds key and certificate.
	key := filepath.Join(work, "id_ed25519")
	mustRun(t, work, nil, sshKeygen, "-q", "-t", "ed25519", "-N", "", "-f", key)
	r = run(t, work, agentEnv, bxpBin, "ssh", "--agent", "--key", key+".pub", "--token", c.token("ssh-user", "ops"))
	if r.code != 0 {
		t.Fatalf("bxp ssh --agent --key:\n%s", r)
	}
	if _, err := os.Stat(key + "-cert.pub"); err != nil {
		t.Errorf("no certificate file with --key: %v", err)
	}
	// The agent holds a certificate for this very key (the agent lists a
	// key added with its certificate once, as the certificate).
	listed := listAgent()
	if n := strings.Count(listed, "-cert-v01@openssh.com"); n != 2 {
		t.Fatalf("%d certificates in the agent, want 2:\n%s", n, listed)
	}
	fingerprint := strings.Fields(mustRun(t, work, nil, sshKeygen, "-l", "-f", key+".pub").stdout)[1]
	found := false
	for i, line := range strings.Split(strings.TrimSpace(listed), "\n") {
		certFile := filepath.Join(t.TempDir(), "agent-cert-"+string(rune('a'+i))+".pub")
		writeFile(t, certFile, line+"\n")
		if strings.Contains(mustRun(t, work, nil, sshKeygen, "-L", "-f", certFile).stdout, fingerprint) {
			found = true
		}
	}
	if !found {
		t.Errorf("no certificate in the agent is for %s (%s):\n%s", key, fingerprint, listed)
	}
}

// waitForSocket waits until a Unix socket exists.
func waitForSocket(t *testing.T, path string) {
	t.Helper()
	for range 100 {
		if _, err := os.Stat(path); err == nil {
			return
		}
		sleepShort()
	}
	t.Fatalf("%s did not appear", path)
}

// "bxp renew" on an SSH host certificate: a new certificate for the same
// host key (a host keeps its key: clients know it), and the principals
// and kind stay.
func TestSSHHostRenew(t *testing.T) {
	sshKeygen := tool(t, "ssh-keygen")
	c := newCA(t, "")
	c.start()
	c.trust()
	dir := t.TempDir()
	hostKey := filepath.Join(dir, "ssh_host_ed25519_key")
	mustRun(t, dir, nil, sshKeygen, "-q", "-t", "ed25519", "-N", "", "-f", hostKey)
	c.client("ssh", "--token", c.token("ssh-host", "web1.e2e.localhost"), "--key", hostKey+".pub")
	certFile := hostKey + "-cert.pub"
	describe := func() string { return mustRun(t, dir, nil, sshKeygen, "-L", "-f", certFile).stdout }
	before := describe()
	keyBefore := string(readFile(t, hostKey))

	c.client("renew", "--cert", certFile, "--key", hostKey, "--force")
	after := describe()
	if after == before {
		t.Fatal("the certificate did not change")
	}
	if string(readFile(t, hostKey)) != keyBefore {
		t.Error("renewal changed the host key")
	}
	field := func(text, name string) string {
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), name+":") {
				return strings.TrimSpace(line)
			}
		}
		return ""
	}
	for _, f := range []string{"Type", "Public key"} {
		if field(after, f) != field(before, f) {
			t.Errorf("%s changed: %q -> %q", f, field(before, f), field(after, f))
		}
	}
	if !strings.Contains(after, "host certificate") || !strings.Contains(after, "web1.e2e.localhost") {
		t.Errorf("renewed certificate:\n%s", after)
	}
	if field(after, "Serial") == field(before, "Serial") {
		t.Error("the serial number did not change")
	}
}
