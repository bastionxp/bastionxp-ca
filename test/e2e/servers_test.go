// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && !windows

package e2e

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// ACME clients built into servers: they get their certificates themselves,
// with no separate program. Go's autocert and Caddy each use their own ACME
// code (autocert x/crypto/acme, Caddy CertMagic), not certbot's or lego's.

// A Go web server with autocert gets its certificate from the real CA
// during the first TLS handshake, with tls-alpn-01 on port 443; curl and
// openssl accept it; after a restart the server uses the cached
// certificate without a new order.
func TestAutocert(t *testing.T) {
	needPort(t, 443)
	curl := tool(t, "curl")
	c := newCA(t, acmeConfig)
	c.start()
	const name = "autocert.e2e.localhost"
	cacheDir := t.TempDir()

	// serve runs a web server as a Go program would, with a new Manager
	// on the same cache each time, as after a restart.
	serve := func() (stop func()) {
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(name),
			Cache:      autocert.DirCache(cacheDir),
			Client:     &acme.Client{DirectoryURL: c.url + "/acme/directory", HTTPClient: c.httpsClient()},
		}
		l, err := net.Listen("tcp", ":443")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				io.WriteString(w, "hello from autocert")
			}),
			TLSConfig: m.TLSConfig(),
		}
		go srv.ServeTLS(l, "", "")
		return func() { srv.Close() }
	}
	visit := func() {
		t.Helper()
		r := mustRun(t, c.dir, nil, curl, "--silent", "--show-error", "--max-time", "60",
			"--cacert", c.root, "--resolve", name+":443:127.0.0.1", "https://"+name+"/")
		if r.stdout != "hello from autocert" {
			t.Fatalf("curl got %q", r.stdout)
		}
	}
	orders := func() int {
		return strings.Count(c.admin("list", "acme-orders").stdout, name+"  valid  tls-alpn-01")
	}

	stop := serve()
	visit() // the first handshake gets the certificate
	stop()
	// autocert keeps the key and the chain in one file, named after the name.
	certFile := filepath.Join(cacheDir, name)
	first := c.verifyWithOpenSSL(certFile, name)
	if n := orders(); n != 1 {
		t.Fatalf("%d valid tls-alpn-01 orders for %s, want 1", n, name)
	}

	stop = serve()
	defer stop()
	visit()
	if again := readCerts(t, certFile)[0]; again.SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Error("after a restart autocert got a new certificate instead of using its cache")
	}
	if n := orders(); n != 1 {
		t.Errorf("after a restart: %d orders, want still 1", n)
	}
}

// Caddy gets certificates from the real CA and serves them: one site set
// up as the documentation shows (a snippet with the tls directive's ca and
// ca_root, imported by the site), and two with their own ACME issuer, one
// proved only with http-01 and one only with tls-alpn-01; curl and openssl
// accept them.
//
// The documentation's form is per site because Caddy gives internal names
// (.localhost, .local, .internal, .home.arpa) and IP addresses its own
// internal CA's certificates when the ACME CA is set only in the global
// options.
func TestCaddy(t *testing.T) {
	needPort(t, 80)
	needPort(t, 443)
	caddy := tool(t, "caddy")
	curl := tool(t, "curl")
	c := newCA(t, acmeConfig)
	c.start()
	dir := t.TempDir()
	storage := filepath.Join(dir, "storage")

	// Two sites with their own issuer, one per challenge: each turns the
	// other challenge off.
	site := func(name, disable string) string {
		return fmt.Sprintf(`%s {
	tls {
		issuer acme {
			dir %s/acme/directory
			trusted_roots %s
			email e2e@example.com
			%s
		}
	}
	respond "hello from %s"
}
`, name, c.url, c.root, disable, name)
	}
	const docName, httpName, alpnName = "caddy.e2e.localhost", "caddy-http.e2e.localhost", "caddy-alpn.e2e.localhost"
	caddyfile := filepath.Join(dir, "Caddyfile")
	writeFile(t, caddyfile, fmt.Sprintf(`{
	admin off
	skip_install_trust
	http_port 80
	https_port 443
	storage file_system %s
}

(bastionxp-ca) {
	tls {
		ca %s/acme/directory
		ca_root %s
	}
}

%s {
	import bastionxp-ca
	respond "hello from %s"
}

`, storage, c.url, c.root, docName, docName)+site(httpName, "disable_tlsalpn_challenge")+"\n"+site(alpnName, "disable_http_challenge"))

	cmd := exec.Command(caddy, "run", "--config", caddyfile, "--adapter", "caddyfile")
	cmd.Dir = dir
	// Caddy keeps its own files under HOME and XDG_*; keep them here.
	cmd.Env = append(os.Environ(), "HOME="+dir, "XDG_DATA_HOME="+dir, "XDG_CONFIG_HOME="+dir)
	logs := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
			<-done
		}
		if t.Failed() {
			t.Logf("caddy log:\n%s", logs)
		}
	})

	for _, tc := range []struct{ name, challenge string }{
		{docName, ""}, // either challenge: Caddy chooses
		{httpName, "http-01"},
		{alpnName, "tls-alpn-01"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := c.in(t)
			// Caddy gets its certificates in the background after it starts.
			var r result
			deadline := time.Now().Add(60 * time.Second)
			for time.Now().Before(deadline) {
				r = run(t, dir, nil, curl, "--silent", "--show-error", "--max-time", "10",
					"--cacert", c.root, "--resolve", tc.name+":443:127.0.0.1", "https://"+tc.name+"/")
				if r.code == 0 {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
			if r.code != 0 || r.stdout != "hello from "+tc.name {
				t.Fatalf("curl https://%s/:\n%s", tc.name, r)
			}

			files, _ := filepath.Glob(filepath.Join(storage, "certificates", "*", tc.name, tc.name+".crt"))
			if len(files) != 1 {
				t.Fatalf("Caddy's certificate for %s: found %v", tc.name, files)
			}
			c.verifyWithOpenSSL(files[0], tc.name)
			if orders := c.admin("list", "acme-orders").stdout; !strings.Contains(orders, tc.name+"  valid  "+tc.challenge) {
				t.Errorf("bxp list acme-orders lacks %s proved with %s:\n%s", tc.name, tc.challenge, orders)
			}
		})
	}
}
