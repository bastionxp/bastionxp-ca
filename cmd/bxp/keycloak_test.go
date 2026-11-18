// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

// Tests of the browser login against a real identity provider: Keycloak in
// Docker. They are off by default, because they need Docker and take a
// minute to start. Run them with:
//
//	make test-keycloak
//
// or BXP_TEST_KEYCLOAK=1 go test ./cmd/bxp -run Keycloak -v
//
// The test starts Keycloak, starts a CA, then creates a realm with the CA's
// exact redirect URI, people and groups through Keycloak's admin API. A
// small "browser" fills in Keycloak's real login form. The container is
// removed at the end.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/config"
)

const (
	keycloakImage  = "quay.io/keycloak/keycloak:26.0.7"
	keycloakRealm  = "bastionxp-ca"
	keycloakClient = "bastionxp-ca"
	keycloakSecret = "bastionxp-ca-client-secret"
)

// startKeycloak starts Keycloak and returns its address,
// e.g. "http://127.0.0.1:55001".
func startKeycloak(t *testing.T) string {
	t.Helper()
	if os.Getenv("BXP_TEST_KEYCLOAK") == "" {
		t.Skip("set BXP_TEST_KEYCLOAK=1 to test against Keycloak in Docker")
	}
	// Only the standard output is the answer: "docker run" writes the
	// progress of pulling the image to the error output.
	run := func(args ...string) string {
		var stderr bytes.Buffer
		cmd := exec.Command("docker", args...)
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("docker %s: %v\n%s%s", strings.Join(args, " "), err, out, stderr.Bytes())
		}
		return strings.TrimSpace(string(out))
	}
	id := run("run", "-d", "-p", "127.0.0.1::8080",
		"-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin", "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=admin",
		keycloakImage, "start-dev")
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", "--tail", "40", id).CombinedOutput()
			t.Logf("Keycloak log:\n%s", out)
		}
		_ = exec.Command("docker", "rm", "-f", id).Run()
	})
	port, _, _ := strings.Cut(run("port", id, "8080/tcp"), "\n")
	base := "http://" + strings.TrimSpace(port)

	deadline := time.Now().Add(4 * time.Minute)
	for {
		resp, err := http.Get(base + "/realms/master")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return base
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("Keycloak did not come up in time")
		}
		time.Sleep(2 * time.Second)
	}
}

// createRealm creates the realm of the tests, with the CA registered as a
// confidential client with its exact callback address:
//
//	alice   no group      (the CA's rules name her: alice, deploy)
//	bob     linux-users   -> bob
//	carol   ca-admins     -> admin
//	eve     marketing     -> nothing
func createRealm(t *testing.T, base, redirectURI string) {
	t.Helper()
	form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"}, "password": {"admin"}}
	resp, err := http.PostForm(base+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatal(err)
	}
	var admin struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(resp.Body).Decode(&admin)
	resp.Body.Close()
	if err != nil || admin.AccessToken == "" {
		t.Fatalf("no admin token: %v (status %s)", err, resp.Status)
	}

	user := func(name string, groups ...string) map[string]any {
		paths := []string{}
		for _, g := range groups {
			paths = append(paths, "/"+g)
		}
		// With all of the profile filled in, Keycloak asks nothing
		// more at the first login.
		return map[string]any{
			"username": name, "enabled": true,
			"email": name + "@corp.example.com", "emailVerified": true,
			"firstName": strings.ToUpper(name[:1]) + name[1:], "lastName": "Test",
			"credentials": []map[string]any{{"type": "password", "value": name + "-pw", "temporary": false}},
			"groups":      paths,
		}
	}
	realm := map[string]any{
		"realm": keycloakRealm, "enabled": true,
		// The test talks plain HTTP to Keycloak on this machine.
		"sslRequired": "none",
		"groups":      []map[string]any{{"name": "linux-users"}, {"name": "ca-admins"}, {"name": "marketing"}},
		"users": []map[string]any{
			user("alice"), user("bob", "linux-users"), user("carol", "ca-admins"), user("eve", "marketing"),
		},
		"clients": []map[string]any{{
			"clientId": keycloakClient, "enabled": true, "protocol": "openid-connect",
			"publicClient": false, "clientAuthenticatorType": "client-secret", "secret": keycloakSecret,
			"standardFlowEnabled": true, "directAccessGrantsEnabled": false,
			"redirectUris": []string{redirectURI},
			"attributes":   map[string]string{"pkce.code.challenge.method": "S256"},
			"protocolMappers": []map[string]any{{
				"name": "groups", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper",
				"config": map[string]string{
					"claim.name": "groups", "full.path": "false",
					"id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true",
				},
			}},
		}},
	}
	body, err := json.Marshal(realm)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, base+"/admin/realms", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+admin.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create realm: %s\n%s", resp.Status, answer)
	}
}

// formBrowser is a browser that fills in Keycloak's login form. It keeps
// its cookies, so a second login finds the Keycloak session, as a real
// browser would.
type formBrowser struct {
	t                  *testing.T
	client             *http.Client
	username, password string

	mu       sync.Mutex
	forms    int // how many times the login form was filled in
	running  sync.WaitGroup
	lastPage string
}

var loginForm = regexp.MustCompile(`(?s)<form[^>]*id="kc-form-login"[^>]*>`)
var formAction = regexp.MustCompile(`action="([^"]+)"`)

func newFormBrowser(t *testing.T, rootFile, username string) *formBrowser {
	t.Helper()
	rootPEM, err := os.ReadFile(rootFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(rootPEM)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	b := &formBrowser{
		t: t, username: username, password: username + "-pw",
		client: &http.Client{
			Timeout:   30 * time.Second,
			Jar:       jar,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}},
		},
	}
	t.Cleanup(b.running.Wait)
	return b
}

// open is what the command calls to open the browser.
func (b *formBrowser) open(address string) error {
	b.running.Add(1)
	go func() {
		defer b.running.Done()
		if err := b.visit(address); err != nil {
			b.t.Errorf("browser: %v", err)
		}
	}()
	return nil
}

func (b *formBrowser) visit(address string) error {
	resp, err := b.client.Get(address)
	for range 3 {
		if err != nil {
			return err
		}
		page, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		form := loginForm.Find(page)
		if form == nil {
			b.mu.Lock()
			b.lastPage = string(page)
			b.mu.Unlock()
			return nil
		}
		action := formAction.FindSubmatch(form)
		if action == nil {
			return fmt.Errorf("login form without an action: %s", form)
		}
		b.mu.Lock()
		b.forms++
		b.mu.Unlock()
		resp, err = b.client.PostForm(html.UnescapeString(string(action[1])),
			url.Values{"username": {b.username}, "password": {b.password}, "credentialId": {""}})
	}
	return fmt.Errorf("Keycloak keeps showing the login form for %s", b.username)
}

func (b *formBrowser) formsFilled() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.forms
}

// Browser logins against a real Keycloak: principals from a group, then a
// second login without the form; principals from a rule by name; no matching
// rule refused; an admin by group gets a host token; a non-admin is refused
// one.
func TestKeycloak(t *testing.T) {
	base := startKeycloak(t)
	issuer := base + "/realms/" + keycloakRealm
	testCA := startTestCA(t, func(cfg *config.Config) {
		cfg.OIDC = config.OIDC{
			Issuer: issuer, ClientID: keycloakClient, ClientSecret: keycloakSecret,
			UsernameClaim: "preferred_username", GroupsClaim: "groups",
			Scopes: []string{"openid", "profile", "email"},
		}
	})
	createRealm(t, base, testCA.url+"/v1/oidc/callback")
	t.Setenv(envClientDir, t.TempDir())

	as := func(browser *formBrowser) connection {
		return connection{url: testCA.url, root: testCA.root, prompt: io.Discard, openBrowser: browser.open}
	}
	sshCert := func(t *testing.T, conn connection) (*ssh.Certificate, error) {
		keyFile := writeSSHKey(t, t.TempDir())
		if err := runSSH(context.Background(), io.Discard, conn, sshOptions{keyFile: keyFile, template: "ssh-user"}); err != nil {
			return nil, err
		}
		return sshCertAt(t, keyFile), nil
	}

	t.Run("principal from a group", func(t *testing.T) {
		browser := newFormBrowser(t, testCA.root, "bob")
		cert, err := sshCert(t, as(browser))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(cert.ValidPrincipals, []string{"bob"}) || !strings.HasPrefix(cert.KeyId, "bob-") {
			t.Errorf("principals %v, key ID %q", cert.ValidPrincipals, cert.KeyId)
		}
		// The second time, Keycloak knows the browser: no form.
		if _, err := sshCert(t, as(browser)); err != nil {
			t.Fatal(err)
		}
		if n := browser.formsFilled(); n != 1 {
			t.Errorf("login form filled in %d times, want once (then the Keycloak session)", n)
		}
	})

	t.Run("principals from a rule by name", func(t *testing.T) {
		cert, err := sshCert(t, as(newFormBrowser(t, testCA.root, "alice")))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(cert.ValidPrincipals, []string{"alice", "deploy"}) {
			t.Errorf("principals = %v, want alice, deploy", cert.ValidPrincipals)
		}
	})

	t.Run("no matching rule", func(t *testing.T) {
		_, err := sshCert(t, as(newFormBrowser(t, testCA.root, "eve")))
		if err == nil || !strings.Contains(err.Error(), "may not use this CA") {
			t.Errorf("error = %v, want a refusal", err)
		}
	})

	t.Run("admin by group gets a host token", func(t *testing.T) {
		var out bytes.Buffer
		opts := tokenOptions{template: "ssh-host", names: []string{"web1.example.com"}, validFor: time.Hour}
		if err := runRemoteToken(context.Background(), &out, as(newFormBrowser(t, testCA.root, "carol")), opts); err != nil {
			t.Fatal(err)
		}
		server := connection{url: testCA.url, root: testCA.root, token: strings.TrimSpace(out.String()), prompt: io.Discard}
		keyFile := writeSSHKey(t, t.TempDir())
		if err := runSSH(context.Background(), io.Discard, server, sshOptions{keyFile: keyFile}); err != nil {
			t.Fatal(err)
		}
		if cert := sshCertAt(t, keyFile); cert.CertType != ssh.HostCert {
			t.Errorf("certificate type = %d, want a host certificate", cert.CertType)
		}
	})

	t.Run("not an admin", func(t *testing.T) {
		var out bytes.Buffer
		opts := tokenOptions{template: "ssh-host", names: []string{"web1.example.com"}, validFor: time.Hour}
		err := runRemoteToken(context.Background(), &out, as(newFormBrowser(t, testCA.root, "bob")), opts)
		if err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("error = %v, want a refusal", err)
		}
	})
}
