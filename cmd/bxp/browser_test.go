// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/ca"
)

// testBrowser plays a person's web browser. It trusts the CA's root
// certificate and follows redirects, like a real one.
type testBrowser struct {
	t      *testing.T
	client *http.Client

	mu      sync.Mutex
	visited []string // every address the browser was sent to
	page    string   // the last page shown
	done    chan struct{}
}

func newTestBrowser(t *testing.T, rootFile string) *testBrowser {
	t.Helper()
	rootPEM, err := os.ReadFile(rootFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(rootPEM)

	b := &testBrowser{t: t, done: make(chan struct{})}
	b.client = &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			b.mu.Lock()
			b.visited = append(b.visited, req.URL.String())
			b.mu.Unlock()
			return nil
		},
	}
	return b
}

// open is what the command calls to open the browser. Like a real
// browser it returns at once and loads the page in the background.
func (b *testBrowser) open(address string) error {
	b.mu.Lock()
	b.visited = append(b.visited, address)
	b.mu.Unlock()
	go func() {
		defer close(b.done)
		resp, err := b.client.Get(address)
		if err != nil {
			b.t.Errorf("browser: %v", err)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		b.mu.Lock()
		b.page = string(body)
		b.mu.Unlock()
	}()
	return nil
}

// lastPage waits for the browser to finish and returns what it shows.
func (b *testBrowser) lastPage() string {
	select {
	case <-b.done:
	case <-time.After(10 * time.Second):
		b.t.Fatal("the browser never finished loading")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.page
}

// hosts returns the host of every address the browser was sent to.
func (b *testBrowser) hosts() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var hosts []string
	for _, address := range b.visited {
		if u, err := url.Parse(address); err == nil {
			hosts = append(hosts, u.Host)
		}
	}
	return hosts
}

// browserAs returns connection settings without a token, for a person
// whose browser is logged in at the identity provider as username.
func (c *testCA) browserAs(t *testing.T, username string) (connection, *testBrowser) {
	t.Helper()
	c.idp.SignInAs(username)
	browser := newTestBrowser(t, c.root)
	return connection{url: c.url, root: c.root, prompt: io.Discard, openBrowser: browser.open}, browser
}

// The main road for a user: one command, a login in the browser, an SSH
// certificate.
func TestSSHWithBrowserLogin(t *testing.T) {
	testCA := startTestCA(t)
	conn, browser := testCA.browserAs(t, "alice")
	var prompt bytes.Buffer
	conn.prompt = &prompt

	keyFile := writeSSHKey(t, t.TempDir())
	var out bytes.Buffer
	if err := runSSH(context.Background(), &out, conn, sshOptions{keyFile: keyFile, template: "ssh-user"}); err != nil {
		t.Fatal(err)
	}

	certLine, err := os.ReadFile(strings.TrimSuffix(keyFile, ".pub") + "-cert.pub")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := parseSSHCert(string(certLine))
	if err != nil {
		t.Fatal(err)
	}
	if cert.CertType != ssh.UserCert {
		t.Errorf("certificate type = %d, want a user certificate", cert.CertType)
	}
	if got := strings.Join(cert.ValidPrincipals, ","); got != "alice,deploy" {
		t.Errorf("principals = %s, want alice,deploy (what the configuration lists for alice)", got)
	}
	if !strings.HasPrefix(cert.KeyId, "alice-") {
		t.Errorf("key ID = %q, want it to start with the login name, alice-", cert.KeyId)
	}

	if page := browser.lastPage(); !strings.Contains(page, "Login succeeded") {
		t.Errorf("the browser shows:\n%s", page)
	}
	// The address is printed too, for when the browser does not open.
	if !strings.Contains(prompt.String(), testCA.url+api.OIDCLoginPath) {
		t.Errorf("the prompt does not show the login address:\n%s", prompt.String())
	}
	// The instructions must not be mixed into the normal output.
	if strings.Contains(out.String(), "browser") {
		t.Errorf("the normal output contains the login instructions:\n%s", out.String())
	}
	// Nothing is kept on disk after the login: no session, no token.
	entries, _ := os.ReadDir(filepath.Dir(keyFile))
	if len(entries) != 2 {
		t.Errorf("%d files next to the key, want 2 (the key and its certificate)", len(entries))
	}
}

// After a browser login, a user cannot get someone else's principal, a host
// certificate, a TLS certificate or a token for someone else; the command
// and the browser page both say it is not allowed, and no certificate file
// is written.
func TestBrowserLoginUserIsHeldToTheirOwnPrincipals(t *testing.T) {
	testCA := startTestCA(t)
	ctx := context.Background()
	keyFile := writeSSHKey(t, t.TempDir())
	certFile := strings.TrimSuffix(keyFile, ".pub") + "-cert.pub"

	tests := map[string]func(conn connection) error{
		"principal of someone else": func(conn connection) error {
			return runSSH(ctx, io.Discard, conn, sshOptions{keyFile: keyFile, template: "ssh-user", principals: []string{"root"}})
		},
		"host certificate": func(conn connection) error {
			return runSSH(ctx, io.Discard, conn, sshOptions{keyFile: keyFile, template: "ssh-host", principals: []string{"alice"}})
		},
		"TLS certificate": func(conn connection) error {
			return runTLS(ctx, io.Discard, conn, tlsOptions{names: []string{"web.example.com"}, template: "tls-server", outDir: t.TempDir()})
		},
		"token for someone else": func(conn connection) error {
			return runRemoteToken(ctx, io.Discard, conn, tokenOptions{template: "ssh-user", names: []string{"root"}})
		},
	}
	for name, request := range tests {
		t.Run(name, func(t *testing.T) {
			conn, browser := testCA.browserAs(t, "alice")
			err := request(conn)
			if err == nil || !strings.Contains(err.Error(), "not allowed") {
				t.Errorf("error = %v, want the CA's refusal", err)
			}
			// The person sees the reason in the browser as well.
			if page := browser.lastPage(); !strings.Contains(page, "Login failed") || !strings.Contains(page, "not allowed") {
				t.Errorf("the browser shows:\n%s", page)
			}
		})
	}
	if _, err := os.Stat(certFile); err == nil {
		t.Error("a certificate file was written despite the refusals")
	}
}

// A browser login by someone not in the configuration fails with the CA's
// refusal, by name.
func TestBrowserLoginIsRefusedForPeopleNotInTheConfiguration(t *testing.T) {
	testCA := startTestCA(t)
	conn, _ := testCA.browserAs(t, "mallory")

	keyFile := writeSSHKey(t, t.TempDir())
	err := runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: keyFile, template: "ssh-user"})
	if err == nil || !strings.Contains(err.Error(), "mallory may not use this CA") {
		t.Fatalf("error = %v, want the CA's refusal", err)
	}
}

// A browser login cancelled at the provider fails and says so.
func TestBrowserLoginCancelledAtTheProvider(t *testing.T) {
	testCA := startTestCA(t)
	conn, _ := testCA.browserAs(t, "") // presses Cancel at the provider

	keyFile := writeSSHKey(t, t.TempDir())
	err := runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: keyFile, template: "ssh-user"})
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("error = %v, want one that says the login was cancelled", err)
	}
}

// An admin gets a token from their own machine and hands it to a server,
// which uses it like any other token.
func TestAdminGetsTokenWithBrowserLogin(t *testing.T) {
	testCA := startTestCA(t)
	admin, _ := testCA.browserAs(t, "ganesh")

	var out bytes.Buffer
	opts := tokenOptions{template: "ssh-host", names: []string{"web1.example.com"}, validFor: time.Hour}
	if err := runRemoteToken(context.Background(), &out, admin, opts); err != nil {
		t.Fatal(err)
	}
	oneTime := strings.TrimSpace(out.String())
	if oneTime == "" || strings.ContainsAny(oneTime, " \n") {
		t.Fatalf("the output is not just a token: %q", out.String())
	}

	// The server that gets the token has no browser and no account.
	server := connection{url: testCA.url, root: testCA.root, token: oneTime, prompt: io.Discard}
	keyFile := writeSSHKey(t, t.TempDir())
	if err := runSSH(context.Background(), io.Discard, server, sshOptions{keyFile: keyFile}); err != nil {
		t.Fatal(err)
	}
	certLine, err := os.ReadFile(strings.TrimSuffix(keyFile, ".pub") + "-cert.pub")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := parseSSHCert(string(certLine))
	if err != nil {
		t.Fatal(err)
	}
	if cert.CertType != ssh.HostCert || len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "web1.example.com" {
		t.Errorf("got certificate type %d for %v, want a host certificate for web1.example.com", cert.CertType, cert.ValidPrincipals)
	}
	// The certificate is the host's, not the admin's.
	if !strings.HasPrefix(cert.KeyId, "web1.example.com-") {
		t.Errorf("key ID = %q, want it to start with web1.example.com-", cert.KeyId)
	}
}

// "bxp token" from afar always logs in. A one-time token given with --token
// must not be used to make another token.
func TestRemoteTokenIgnoresAGivenToken(t *testing.T) {
	testCA := startTestCA(t)
	conn, browser := testCA.browserAs(t, "alice") // not an admin
	conn.token = testCA.connection(t, "ssh-host", "web1").token

	err := runRemoteToken(context.Background(), io.Discard, conn, tokenOptions{template: "ssh-host", names: []string{"web1"}})
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("error = %v, want the CA's refusal for a non-admin", err)
	}
	if len(browser.hosts()) == 0 {
		t.Error("the browser was not opened: the given token was used instead of a login")
	}
}

// Asking for a token through a browser login needs --name.
func TestRemoteTokenNeedsNames(t *testing.T) {
	conn := connection{url: "https://ca.example.com", prompt: io.Discard}
	err := runRemoteToken(context.Background(), io.Discard, conn, tokenOptions{template: "ssh-host"})
	if err == nil || !strings.Contains(err.Error(), "--name") {
		t.Errorf("error = %v, want one that mentions --name", err)
	}
}

// An admin gets a TLS certificate and key through a browser login.
func TestAdminRequestsTLSWithBrowserLogin(t *testing.T) {
	testCA := startTestCA(t)
	admin, _ := testCA.browserAs(t, "ganesh")

	outDir := t.TempDir()
	opts := tlsOptions{names: []string{"web.example.com"}, template: "tls-server", outDir: outDir}
	if err := runTLS(context.Background(), io.Discard, admin, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(outDir, "web.example.com.crt"), filepath.Join(outDir, "web.example.com.key")); err != nil {
		t.Error(err)
	}
}

// With --token there is no login: the browser must stay closed.
func TestNoBrowserWhenATokenIsGiven(t *testing.T) {
	testCA := startTestCA(t)
	conn := testCA.connection(t, "ssh-user", "alice")
	opened := false
	conn.openBrowser = func(string) error { opened = true; return nil }

	keyFile := writeSSHKey(t, t.TempDir())
	if err := runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: keyFile}); err != nil {
		t.Fatal(err)
	}
	if opened {
		t.Error("the browser was opened although a token was given")
	}
}

// loginInProgress starts a command that waits for a browser login and
// returns the login address it printed, without opening any browser.
func loginInProgress(t *testing.T, testCA *testCA, ctx context.Context) (loginURL *url.URL, finished <-chan error) {
	t.Helper()
	prompt := &lockedBuffer{}
	conn := connection{url: testCA.url, root: testCA.root, prompt: prompt, openBrowser: func(string) error { return nil }}
	keyFile := writeSSHKey(t, t.TempDir())

	done := make(chan error, 1)
	go func() {
		done <- runSSH(ctx, io.Discard, conn, sshOptions{keyFile: keyFile, template: "ssh-user"})
	}()

	address := regexp.MustCompile(`https://\S+`)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if found := address.FindString(prompt.String()); found != "" && strings.Contains(prompt.String(), "Waiting") {
			u, err := url.Parse(found)
			if err != nil {
				t.Fatal(err)
			}
			return u, done
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the command never printed a login address")
	return nil, nil
}

// lockedBuffer is a bytes.Buffer that two goroutines may use.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Any web page can make a person's browser call an address on 127.0.0.1.
// A reply that does not carry the secret state of this login must be
// ignored, and the command must keep waiting for the real one.
func TestCallbackIgnoresRepliesThatAreNotFromThisLogin(t *testing.T) {
	testCA := startTestCA(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loginURL, finished := loginInProgress(t, testCA, ctx)
	callback := loginURL.Query().Get(api.LoginCallback)

	// Somebody else's token, pushed at the waiting command.
	foreign := testCA.connection(t, "ssh-user", "root").token
	for name, query := range map[string]url.Values{
		"no state":    {api.ResultToken: {foreign}},
		"wrong state": {api.ResultToken: {foreign}, api.ResultState: {"guess"}},
		"error only":  {api.ResultError: {"go away"}},
	} {
		resp, err := http.Get(callback + "?" + query.Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, resp.StatusCode)
		}
	}

	select {
	case err := <-finished:
		t.Fatalf("the command stopped waiting after a foreign reply (error: %v)", err)
	case <-time.After(200 * time.Millisecond):
		// Still waiting, as it should.
	}

	// The real login still works afterwards.
	testCA.idp.SignInAs("alice")
	newTestBrowser(t, testCA.root).open(loginURL.String())
	select {
	case err := <-finished:
		if err != nil {
			t.Errorf("the real login failed after the foreign replies: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the command did not finish after the real login")
	}
}

// A command waiting for a browser login stops when interrupted.
func TestBrowserLoginStopsOnCtrlC(t *testing.T) {
	testCA := startTestCA(t)
	ctx, cancel := context.WithCancel(context.Background())
	_, finished := loginInProgress(t, testCA, ctx)

	cancel() // the person presses Ctrl-C instead of logging in
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the command did not stop")
	}
}

// What the command sends to the CA when it starts a login.
func TestLoginAddressNamesTheKeyAndAnAddressOnThisMachine(t *testing.T) {
	testCA := startTestCA(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loginURL, _ := loginInProgress(t, testCA, ctx)
	query := loginURL.Query()

	callback, err := url.Parse(query.Get(api.LoginCallback))
	if err != nil {
		t.Fatal(err)
	}
	if callback.Scheme != "http" || callback.Hostname() != "127.0.0.1" || callback.Port() == "" {
		t.Errorf("callback = %s, want http://127.0.0.1:<port>/...", callback)
	}
	if len(query.Get(api.LoginState)) < 32 {
		t.Errorf("state = %q, want a long random value", query.Get(api.LoginState))
	}
	if !strings.HasPrefix(query.Get(api.LoginKey), "SHA256:") {
		t.Errorf("key = %q, want the fingerprint of the SSH key", query.Get(api.LoginKey))
	}
	if query.Get(api.LoginProfile) != "ssh-user" {
		t.Errorf("template = %q, want ssh-user", query.Get(api.LoginProfile))
	}
}

// Against a CA without a login, the command says to use --token at once,
// without opening a browser.
func TestBrowserLoginWhenLoginIsNotSetUp(t *testing.T) {
	// A CA without the oidc section in its configuration.
	cfg := newTestConfig(t)
	if err := runInit(io.Discard, cfg, testInit); err != nil {
		t.Fatal(err)
	}
	opened := false
	conn := connection{
		url:         serveForTest(t, cfg),
		root:        filepath.Join(cfg.DataDir, ca.RootCertFile),
		prompt:      io.Discard,
		openBrowser: func(string) error { opened = true; return nil },
	}

	// The command must say so at once, and not open a browser and wait.
	keyFile := writeSSHKey(t, t.TempDir())
	err := runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: keyFile, template: "ssh-user"})
	if err == nil || !strings.Contains(err.Error(), "--token") {
		t.Errorf("error = %v, want a hint to use --token", err)
	}
	if opened {
		t.Error("the browser was opened")
	}
}
