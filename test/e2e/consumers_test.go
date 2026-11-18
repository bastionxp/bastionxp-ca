// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && !windows

package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The certificates work with the programs that use them, not only in
// their own format: OpenSSH logs in with them, and TLS servers and
// clients accept them.

// background starts a long-running program, and stops it when the test
// ends. Its output is shown if the test fails.
func background(t *testing.T, name string, args ...string) *syncBuffer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, name, args...)
	out := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		cmd.Wait()
		if t.Failed() {
			t.Logf("%s output:\n%s", filepath.Base(name), out)
		}
	})
	return out
}

// waitForPort waits until something listens on 127.0.0.1:port.
func waitForPort(t *testing.T, port int, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s does not listen on port %d", what, port)
}

// OpenSSH: sshd trusts the CA's user key, and presents a host certificate
// from the CA; ssh logs in with a user certificate, and trusts the host
// through the line "bxp trust --ssh" wrote.
func TestOpenSSHLogin(t *testing.T) {
	sshKeygen, ssh := tool(t, "ssh-keygen"), tool(t, "ssh")
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	c := newCA(t, "")
	c.start()
	dir := t.TempDir()
	knownHosts := filepath.Join(dir, "known_hosts")
	c.client("trust", "--ca-url", c.url, "--fingerprint", c.fingerprint(), "--ssh", "--known-hosts", knownHosts)

	newKey := func(name string) string {
		key := filepath.Join(dir, name)
		mustRun(t, dir, nil, sshKeygen, "-q", "-t", "ed25519", "-N", "", "-f", key)
		return key
	}
	// The host: its key and a host certificate for "localhost".
	hostKey := newKey("host_key")
	c.client("ssh", "--token", c.token("ssh-host", "localhost"), "--key", hostKey+".pub")
	// A user certificate for this machine's user: an sshd that does not
	// run as root lets in only the user it runs as.
	userKey := newKey("user_key")
	c.client("ssh", "--token", c.token("ssh-user", me.Username), "--key", userKey+".pub")
	// One for another principal.
	otherKey := newKey("other_key")
	c.client("ssh", "--token", c.token("ssh-user", "someone-else"), "--key", otherKey+".pub")
	// A key without a certificate.
	plainKey := newKey("plain_key")

	port := startSSHD(t, dir, hostKey, filepath.Join(c.dataDir, "ssh_user_ca.pub"))
	login := func(key, known string) result {
		t.Helper()
		return sshLogin(t, ssh, dir, port, me.Username, key, known)
	}

	if r := login(userKey, knownHosts); r.code != 0 || !strings.Contains(r.stdout, "bastionxp-login-ok") {
		t.Fatalf("login with a user certificate:\n%s", r)
	}
	if r := login(otherKey, knownHosts); r.code == 0 {
		t.Errorf("logged in with a certificate for another principal:\n%s", r)
	}
	if r := login(plainKey, knownHosts); r.code == 0 {
		t.Errorf("logged in with a key without a certificate:\n%s", r)
	}
	// Without the @cert-authority line, the host is not trusted.
	empty := filepath.Join(dir, "empty_known_hosts")
	writeFile(t, empty, "")
	if r := login(userKey, empty); r.code == 0 || !strings.Contains(r.stderr, "Host key verification failed") {
		t.Errorf("trusted the host without the CA's line in known_hosts:\n%s", r)
	}
}

// TLS: a server certificate is accepted by openssl and curl for its name,
// and a client certificate opens a server that asks for one (mutual TLS).
func TestTLSHandshake(t *testing.T) {
	openssl, curl := tool(t, "openssl"), tool(t, "curl")
	c := newCA(t, "")
	c.start()
	c.trust()
	dir := t.TempDir()
	intermediate := filepath.Join(c.dataDir, "intermediate.crt")

	const name = "web.e2e.localhost"
	c.client("tls", "--token", c.token("tls-server", name), "--name", name, "--out-dir", dir)
	serverCert, serverKey := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")

	const person = "alice@example.com"
	// No --name: the token's.
	c.client("tls", "--token", c.token("tls-client", person), "--out-dir", dir)
	clientCert, clientKey := filepath.Join(dir, person+".crt"), filepath.Join(dir, person+".key")

	// A plain TLS server.
	port := freePort(t)
	background(t, openssl, "s_server", "-accept", fmt.Sprint(port), "-www",
		"-cert", serverCert, "-key", serverKey, "-cert_chain", intermediate)
	waitForPort(t, port, "openssl s_server")
	address := fmt.Sprintf("127.0.0.1:%d", port)

	check := func(host string) result {
		return run(t, dir, nil, openssl, "s_client", "-connect", address, "-servername", host,
			"-verify_hostname", host, "-CAfile", c.root, "-verify_return_error", "-brief")
	}
	if r := check(name); r.code != 0 || !strings.Contains(r.stderr+r.stdout, "Verification: OK") {
		t.Errorf("openssl s_client:\n%s", r)
	}
	if r := check("other.e2e.localhost"); r.code == 0 {
		t.Errorf("openssl accepted the certificate for another name:\n%s", r)
	}
	resolve := fmt.Sprintf("%s:%d:127.0.0.1", name, port)
	url := fmt.Sprintf("https://%s:%d/", name, port)
	if r := run(t, dir, nil, curl, "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--cacert", c.root, "--resolve", resolve, url); r.code != 0 || r.stdout != "200" {
		t.Errorf("curl:\n%s", r)
	}

	// Mutual TLS: the server asks for a client certificate from this CA.
	mtlsPort := freePort(t)
	background(t, openssl, "s_server", "-accept", fmt.Sprint(mtlsPort), "-www",
		"-cert", serverCert, "-key", serverKey, "-cert_chain", intermediate,
		"-Verify", "2", "-verify_return_error", "-CAfile", c.root)
	waitForPort(t, mtlsPort, "openssl s_server (mutual TLS)")
	mtlsAddress := fmt.Sprintf("127.0.0.1:%d", mtlsPort)

	// Asked with an HTTP request: with TLS 1.3 the server says no to a
	// client certificate only after the handshake, on the first request.
	// (Not curl: the LibreSSL in macOS's curl cannot read the TLS 1.3
	// certificate request of OpenSSL 3.)
	viaOpenSSL := func(cert, key string) bool {
		args := []string{"s_client", "-connect", mtlsAddress, "-servername", name,
			"-CAfile", c.root, "-verify_return_error", "-quiet"}
		if cert != "" {
			args = append(args, "-cert", cert, "-key", key, "-cert_chain", intermediate)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, openssl, args...)
		cmd.Stdin = strings.NewReader("GET / HTTP/1.0\r\n\r\n")
		out, _ := cmd.CombinedOutput()
		return strings.Contains(string(out), "HTTP/1.0 200 ok")
	}
	// Go's crypto/tls, as Go services use it, with the files as bxp wrote
	// them.
	viaGo := func(cert, key string) bool {
		config := &tls.Config{RootCAs: c.httpsClient().Transport.(*http.Transport).TLSClientConfig.RootCAs, ServerName: name}
		if cert != "" {
			pair, err := tls.LoadX509KeyPair(cert, key)
			if err != nil {
				t.Fatalf("Go cannot load %s: %v", cert, err)
			}
			config.Certificates = []tls.Certificate{pair}
		}
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: config}}
		resp, err := client.Get("https://" + mtlsAddress + "/")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
	for client, connects := range map[string]func(cert, key string) bool{"openssl": viaOpenSSL, "Go": viaGo} {
		if !connects(clientCert, clientKey) {
			t.Errorf("%s: mutual TLS with a tls-client certificate failed", client)
		}
		if connects("", "") {
			t.Errorf("%s: mutual TLS let a client in without a certificate", client)
		}
		// A server certificate is not for clients.
		if connects(serverCert, serverKey) {
			t.Errorf("%s: mutual TLS let a client in with a tls-server certificate", client)
		}
	}
}

// startSSHD starts sshd as this user on a free port, with a host key and
// its certificate (hostKey + "-cert.pub"), trusting the user CA keys in
// trustedCAKeys. sshd reads that file at each login, so a test may change
// it. It returns the port.
func startSSHD(t *testing.T, dir, hostKey, trustedCAKeys string) int {
	t.Helper()
	sshd := tool(t, "sshd")
	port := freePort(t)
	config := filepath.Join(dir, fmt.Sprintf("sshd_config_%d", port))
	writeFile(t, config, fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
HostCertificate %s-cert.pub
TrustedUserCAKeys %s
AuthorizedKeysFile none
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
PidFile none
LogLevel VERBOSE
`, port, hostKey, hostKey, trustedCAKeys))
	background(t, sshd, "-D", "-e", "-f", config)
	waitForPort(t, port, "sshd")
	return port
}

// sshLogin logs in as username with key (and key-cert.pub, if there is
// one), trusting only the hosts in knownHosts, and runs a command that
// prints "bastionxp-login-ok".
func sshLogin(t *testing.T, ssh, dir string, port int, username, key, knownHosts string) result {
	t.Helper()
	args := []string{"-F", "/dev/null", "-p", fmt.Sprint(port),
		"-o", "IdentitiesOnly=yes", "-i", key,
		"-o", "UserKnownHostsFile=" + knownHosts, "-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes",
		"-o", "PasswordAuthentication=no", "-o", "ConnectTimeout=10",
	}
	if _, err := os.Stat(key + "-cert.pub"); err == nil {
		args = append(args, "-o", "CertificateFile="+key+"-cert.pub")
	}
	args = append(args, username+"@localhost", "echo bastionxp-login-ok")
	return run(t, dir, []string{"SSH_AUTH_SOCK="}, ssh, args...)
}

// loggedIn reports whether an sshLogin worked.
func loggedIn(r result) bool {
	return r.code == 0 && strings.Contains(r.stdout, "bastionxp-login-ok")
}
