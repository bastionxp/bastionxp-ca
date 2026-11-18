// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && !windows

package e2e

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// SIGTERM while requests are running: each one either gets its certificate
// or fails cleanly, the server exits cleanly, and afterwards the database
// is whole and knows every certificate a client got.
func TestGracefulStopUnderLoad(t *testing.T) {
	const requests = 60
	c := newCA(t, "")
	c.start()
	c.trust()
	tokens := make([]string, requests)
	for i := range tokens {
		tokens[i] = c.token("tls-server", fmt.Sprintf("stop%d.e2e.localhost", i))
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var got []string // serials the clients received
	start := make(chan struct{})
	for i := range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			name := fmt.Sprintf("stop%d.e2e.localhost", i)
			out := t.TempDir()
			r := c.bxp("tls", "--token", tokens[i], "--name", name, "--out-dir", out)
			noCrash(t, r)
			if r.code == 0 {
				serial := readCerts(t, filepath.Join(out, name+".crt"))[0].SerialNumber.Text(16)
				mu.Lock()
				got = append(got, serial)
				mu.Unlock()
			} else if strings.TrimSpace(r.stderr) == "" {
				t.Errorf("%s failed without a message", name)
			}
		}()
	}
	close(start)
	time.Sleep(40 * time.Millisecond) // some requests running, some not started
	if err := c.stop(); err != nil {
		t.Errorf("bxp serve did not exit cleanly on SIGTERM under load: %v", err)
	}
	wg.Wait()
	logs := c.logs.String()
	stopAt := strings.Index(logs, "server stopping")
	finishedAfter := 0
	if stopAt >= 0 {
		finishedAfter = strings.Count(logs[stopAt:], "path=/v1/x509/sign status=201")
	}
	t.Logf("%d of %d requests got their certificate; %d of them finished after the stop began", len(got), requests, finishedAfter)

	// Every certificate a client received is in the CA's list.
	list := c.admin("list", "certificates").stdout
	for _, serial := range got {
		if !strings.Contains(list, serial) {
			t.Errorf("a client got certificate %s, but the CA does not list it", serial)
		}
	}
	// The database is whole.
	c.start()
	if r := c.bxp("doctor", "--config", c.config); r.code != 0 || !strings.Contains(r.stdout, "the database is intact") {
		t.Errorf("bxp doctor after the stop:\n%s", r)
	}
}

// The metrics endpoint counts what happens, and asks for its token.
func TestMetrics(t *testing.T) {
	port := freePort(t)
	tokenFile := filepath.Join(t.TempDir(), "metrics-token")
	const metricsToken = "e2e-metrics-token-0123456789"
	writeFile(t, tokenFile, metricsToken+"\n")
	c := newCA(t, fmt.Sprintf("metrics:\n  address: 127.0.0.1:%d\n  token_file: %s\n", port, tokenFile))
	c.start()
	c.trust()
	url := fmt.Sprintf("http://127.0.0.1:%d/metrics", port)
	scrape := func(token string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	// The sum of a metric's values over all its labels.
	total := func(text, metric string) float64 {
		sum := 0.0
		re := regexp.MustCompile(`(?m)^` + metric + `(\{[^}]*\})? ([0-9.e+]+)$`)
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			v, _ := strconv.ParseFloat(m[2], 64)
			sum += v
		}
		return sum
	}

	if status, _ := scrape(""); status != http.StatusUnauthorized {
		t.Errorf("without the token: status %d, want 401", status)
	}
	if status, _ := scrape("wrong"); status != http.StatusUnauthorized {
		t.Errorf("with a wrong token: status %d, want 401", status)
	}
	status, before := scrape(metricsToken)
	if status != http.StatusOK {
		t.Fatalf("with the token: status %d", status)
	}

	c.issueTLS("metrics.e2e.localhost")
	used := c.token("tls-server", "twice.e2e.localhost")
	c.client("tls", "--token", used, "--name", "twice.e2e.localhost", "--out-dir", t.TempDir())
	c.bxp("tls", "--token", used, "--name", "twice.e2e.localhost", "--out-dir", t.TempDir()) // refused

	_, after := scrape(metricsToken)
	if d := total(after, "bastionxp_ca_certificates_issued_total") - total(before, "bastionxp_ca_certificates_issued_total"); d != 2 {
		t.Errorf("certificates issued went up by %v, want 2", d)
	}
	if d := total(after, "bastionxp_ca_requests_refused_total") - total(before, "bastionxp_ca_requests_refused_total"); d < 1 {
		t.Errorf("refusals went up by %v, want at least 1", d)
	}
	if !strings.Contains(after, "bastionxp_ca_http_request_duration_seconds") {
		t.Error("no request durations")
	}
}

// bxp doctor finds what is broken, and says so with its exit status.
func TestDoctorFindsProblems(t *testing.T) {
	c := newCA(t, "")
	doctor := func() result { return c.bxp("doctor", "--config", c.config) }

	// Not running yet: a warning, not a failure.
	if r := doctor(); r.code != 0 || !strings.Contains(r.stdout, "the server does not answer") {
		t.Errorf("a CA not started yet:\n%s", r)
	}
	// A key readable by others: a warning.
	if err := os.Chmod(filepath.Join(c.dataDir, "intermediate.key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := doctor(); !strings.Contains(r.stdout, "readable by others") {
		t.Errorf("a key readable by others:\n%s", r)
	}
	// A missing file: a failure, exit status 1.
	if err := os.Remove(filepath.Join(c.dataDir, "intermediate.crt")); err != nil {
		t.Fatal(err)
	}
	r := doctor()
	noCrash(t, r)
	if r.code != 1 || !strings.Contains(r.stdout, "intermediate.crt is missing") {
		t.Errorf("a missing intermediate certificate:\n%s", r)
	}
}

// Client mistakes and outages: a clear message, a non-zero exit status, no
// crash, and the one-time token is not spent.
func TestClientErrors(t *testing.T) {
	c := newCA(t, "")
	c.start()
	other := newCA(t, "") // another CA, with another root
	other.start()
	const name = "client.e2e.localhost"
	tok := c.token("tls-server", name)
	tls := func(url, root string) result {
		return c.bxp("tls", "--ca-url", url, "--root", root, "--token", tok, "--name", name, "--out-dir", t.TempDir())
	}
	failsWith := func(what string, r result, words ...string) {
		t.Helper()
		noCrash(t, r)
		if r.code == 0 {
			t.Errorf("%s succeeded:\n%s", what, r)
			return
		}
		for _, w := range words {
			if !strings.Contains(strings.ToLower(r.stderr), w) {
				t.Errorf("%s: the message does not mention %q:\n%s", what, w, r)
			}
		}
	}

	// Nothing listens at the address.
	failsWith("a wrong address", tls(fmt.Sprintf("https://127.0.0.1:%d", freePort(t)), c.root), "cannot reach the ca server")
	// Another CA answers: its certificate does not chain to our root.
	failsWith("a server of another CA", tls(other.url, c.root), "is not the ca you trust", "--root")
	// "bxp trust" for another CA does not silently replace the saved one.
	c.trust()
	failsWith("trusting another CA without --force",
		c.bxp("trust", "--ca-url", other.url, "--fingerprint", other.fingerprint()), "--force")

	// After all that, the token still works.
	if r := tls(c.url, c.root); r.code != 0 {
		t.Errorf("the token was spent by the failed attempts:\n%s", r)
	}

	// The CA is down.
	if err := c.stop(); err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(t.TempDir(), "x.crt"), filepath.Join(t.TempDir(), "x.key")
	failsWith("renewal while the CA is down", c.bxp("renew", "--cert", certFile, "--key", keyFile, "--force"), "")
	failsWith("a request while the CA is down", tls(c.url, c.root), "")
	t.Logf("messages:\n%s", strings.Join([]string{
		tls(fmt.Sprintf("https://127.0.0.1:%d", freePort(t)), c.root).stderr,
		tls(other.url, c.root).stderr,
	}, ""))
}
