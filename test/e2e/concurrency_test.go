// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e && !windows

package e2e

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The server and the commands on the CA machine use one SQLite file from
// separate processes. Under load, with revocations, lists and backups
// going on at the same time as issuance, no process fails, nothing is
// lost, and no "database is locked" reaches anyone.
func TestConcurrentProcesses(t *testing.T) {
	const (
		certificates = 150
		parallel     = 16
	)
	c := newCA(t, "")
	c.start()
	c.trust()

	var (
		mu      sync.Mutex
		outputs strings.Builder // everything every process printed
		failed  []string
		issued  []string // serials, as the CA writes them
	)
	note := func(what string, r result) {
		mu.Lock()
		defer mu.Unlock()
		outputs.WriteString(r.stdout + r.stderr)
		if r.code != 0 {
			failed = append(failed, fmt.Sprintf("%s:\n%s", what, r))
		}
	}
	serials := make(chan string, certificates)

	// The issuers: token and certificate, each a process of its own.
	var issuers sync.WaitGroup
	work := make(chan int)
	for range parallel {
		issuers.Add(1)
		go func() {
			defer issuers.Done()
			for i := range work {
				name := fmt.Sprintf("load%d.e2e.localhost", i)
				tok := run(t, c.dir, c.env, bxpBin, "token", "--profile", "tls-server", "--name", name, "--config", c.config)
				note("token "+name, tok)
				if tok.code != 0 {
					continue
				}
				out := t.TempDir()
				r := run(t, c.dir, c.env, bxpBin, "tls", "--token", strings.TrimSpace(tok.stdout), "--name", name, "--out-dir", out)
				note("tls "+name, r)
				if r.code == 0 {
					serial := readCerts(t, filepath.Join(out, name+".crt"))[0].SerialNumber.Text(16)
					mu.Lock()
					issued = append(issued, serial)
					mu.Unlock()
					serials <- serial
				}
			}
		}()
	}

	// Meanwhile, on the CA machine, each in a loop of its own until the
	// issuers are done: revoke every third certificate; list; back up.
	done := make(chan struct{})
	var revoked, backups []string
	var admin sync.WaitGroup
	admin.Add(3)
	go func() {
		defer admin.Done()
		n := 0
		for serial := range serials {
			if n++; n%3 == 0 {
				note("revoke "+serial, run(t, c.dir, c.env, bxpBin, "revoke", serial, "--config", c.config))
				mu.Lock()
				revoked = append(revoked, serial)
				mu.Unlock()
			}
		}
	}()
	loop := func(do func()) {
		defer admin.Done()
		for {
			select {
			case <-done:
				return
			default:
				do()
			}
		}
	}
	go loop(func() {
		note("list", run(t, c.dir, c.env, bxpBin, "list", "certificates", "--config", c.config))
	})
	go loop(func() {
		backup := filepath.Join(t.TempDir(), "backup")
		note("backup", run(t, c.dir, c.env, bxpBin, "backup", "--out", backup, "--config", c.config))
		mu.Lock()
		backups = append(backups, backup)
		mu.Unlock()
	})

	for i := range certificates {
		work <- i
	}
	close(work)
	issuers.Wait()
	close(serials) // the revoker finishes what is left
	close(done)
	admin.Wait()

	for _, f := range failed {
		t.Error(f)
	}
	everything := strings.ToLower(outputs.String() + c.logs.String())
	for _, sign := range []string{"database is locked", "sqlite_busy", "database table is locked"} {
		if strings.Contains(everything, sign) {
			t.Errorf("%q in the output or the server's log", sign)
		}
	}
	if len(issued) != certificates {
		t.Fatalf("%d of %d certificates issued", len(issued), certificates)
	}

	// The CA knows every certificate, and every revocation stuck.
	var list []struct {
		Serial string `json:"serial"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(c.admin("list", "certificates", "--format", "json").stdout), &list); err != nil {
		t.Fatal(err)
	}
	status := map[string]string{}
	for _, cert := range list {
		status[cert.Serial] = cert.Status
	}
	isRevoked := map[string]bool{}
	for _, s := range revoked {
		isRevoked[s] = true
	}
	for _, serial := range issued {
		want := "valid"
		if isRevoked[serial] {
			want = "revoked"
		}
		if status[serial] != want {
			t.Errorf("certificate %s: %q in the list, want %q", serial, status[serial], want)
		}
	}

	// Every backup taken under load is a database that opens and is whole.
	if len(backups) == 0 {
		t.Fatal("no backup was taken during the load")
	}
	for _, backup := range backups {
		config := filepath.Join(filepath.Dir(backup), "backup.yaml")
		writeFile(t, config, "data_dir: "+backup+"\nca:\n  organization: E2E Org\n")
		if r := run(t, c.dir, nil, bxpBin, "list", "certificates", "--config", config); r.code != 0 {
			t.Errorf("backup %s does not open:\n%s", backup, r)
		}
	}
	t.Logf("%d certificates (%d revoked during the load), %d backups", len(issued), len(revoked), len(backups))
}
