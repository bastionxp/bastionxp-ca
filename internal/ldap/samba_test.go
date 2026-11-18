// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ldap_test

// Tests against a real Active Directory: a Samba domain controller in
// Docker. They are off by default, because they need Docker and take a
// minute to start. Run them with:
//
//	make test-samba
//
// or BXP_TEST_SAMBA=1 go test ./internal/ldap -run Samba -v
//
// The test builds the image in testdata/samba, starts a container,
// creates people and groups with samba-tool, and removes the container at
// the end.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/bastionxp/bastionxp-ca/internal/ldap"
)

const (
	sambaImage     = "bastionxp-ca-samba-test"
	sambaBase      = "DC=corp,DC=example,DC=com"
	sambaUsers     = "CN=Users," + sambaBase
	sambaGroups    = "OU=Groups," + sambaBase
	sambaAdmin     = "CN=Administrator," + sambaUsers
	sambaAdminPW   = "Admin-pw-2026!"
	sambaServiceDN = "CN=bastionxp-ca-svc," + sambaUsers
	sambaServicePW = "Svc-pw-2026!"
)

// samba is a running domain controller.
type samba struct {
	ldaps string // ldaps://127.0.0.1:<port>
	ldap  string // ldap://127.0.0.1:<port>, for StartTLS
	roots *x509.CertPool
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	// Only the standard output is the answer: "docker run" and "docker
	// build" write their progress to the error output.
	var stderr bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s%s", strings.Join(args, " "), err, out, stderr.Bytes())
	}
	return strings.TrimSpace(string(out))
}

func startSamba(t *testing.T) *samba {
	t.Helper()
	if os.Getenv("BXP_TEST_SAMBA") == "" {
		t.Skip("set BXP_TEST_SAMBA=1 to test against a Samba AD domain controller in Docker")
	}
	docker(t, "build", "-q", "-t", sambaImage, "testdata/samba")
	// SYS_ADMIN: Samba stores Windows permissions of its SYSVOL folder in
	// "security" extended attributes, which need it.
	id := docker(t, "run", "-d", "--cap-add", "SYS_ADMIN", "--hostname", "dc1",
		"-p", "127.0.0.1::636", "-p", "127.0.0.1::389", sambaImage)
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", "--tail", "40", id).CombinedOutput()
			t.Logf("domain controller log:\n%s", out)
		}
		_ = exec.Command("docker", "rm", "-f", id).Run()
	})

	s := &samba{
		ldaps: "ldaps://" + hostPort(docker(t, "port", id, "636/tcp")),
		ldap:  "ldap://" + hostPort(docker(t, "port", id, "389/tcp")),
	}

	// Provisioning takes a while. Wait until the administrator can bind.
	deadline := time.Now().Add(4 * time.Minute)
	for {
		if ca, err := exec.Command("docker", "exec", id, "cat", "/var/lib/samba/private/tls-test/ca.pem").Output(); err == nil {
			s.roots = x509.NewCertPool()
			s.roots.AppendCertsFromPEM(ca)
			if conn, err := s.dial(); err == nil {
				err = conn.Bind(sambaAdmin, sambaAdminPW)
				conn.Close()
				if err == nil {
					break
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the domain controller did not come up in time")
		}
		time.Sleep(2 * time.Second)
	}

	// The directory of the tests:
	//
	//	OU=Groups:  linux-users  <- alice
	//	            linux-admins <- alice
	//	            ssh-admins   <- linux-admins     (nested)
	//	CN=Users:   ca-admins    <- alice            (outside group_base_dn)
	//	bob is disabled; carol and dave are for the lockout tests.
	script := `set -e
samba-tool ou create OU=Groups 2>/dev/null || samba-tool ou add OU=Groups
samba-tool user create bastionxp-ca-svc '` + sambaServicePW + `'
samba-tool user create alice 'Alice-pw-2026!'
samba-tool user create bob 'Bob-pw-2026!'
samba-tool user disable bob
samba-tool user create carol 'Carol-pw-2026!'
samba-tool user create dave 'Dave-pw-2026!'
samba-tool group add linux-users --groupou=OU=Groups
samba-tool group add linux-admins --groupou=OU=Groups
samba-tool group add ssh-admins --groupou=OU=Groups
samba-tool group add ca-admins
samba-tool group addmembers linux-users alice
samba-tool group addmembers linux-admins alice
samba-tool group addmembers ssh-admins linux-admins
samba-tool group addmembers ca-admins alice
samba-tool domain passwordsettings set --account-lockout-threshold=5 --account-lockout-duration=30 --reset-account-lockout-after=30
`
	docker(t, "exec", id, "sh", "-c", script)
	return s
}

// hostPort takes the first line of "docker port", e.g. "127.0.0.1:55001".
func hostPort(out string) string {
	line, _, _ := strings.Cut(out, "\n")
	return strings.TrimSpace(line)
}

func (s *samba) dial() (*goldap.Conn, error) {
	return goldap.DialURL(s.ldaps, goldap.DialWithTLSConfig(&tls.Config{RootCAs: s.roots, ServerName: "127.0.0.1"}))
}

func (s *samba) config() ldap.Config {
	return ldap.Config{
		URL:               s.ldaps,
		RootCAs:           s.roots,
		BaseDN:            sambaBase,
		BindDN:            sambaServiceDN,
		BindPassword:      sambaServicePW,
		UserFilter:        ldap.DefaultUserFilter,
		UsernameAttribute: ldap.DefaultUsernameAttribute,
		GroupBaseDN:       sambaGroups,
		GroupFilter:       ldap.DefaultGroupFilter,
	}
}

// LDAP logins against a real Samba Active Directory: nested groups,
// StartTLS, sAMAccountName as the username; an empty password, a wrong
// password, a disabled account, an unknown user, a wildcard and a filter
// injection all fail; a wrong service password and an unknown server
// certificate are errors; the CA's failure limit keeps the directory from
// locking the account.
func TestSamba(t *testing.T) {
	dc := startSamba(t)
	ctx := context.Background()
	const remote = "10.0.0.5:5000"

	t.Run("login with nested groups", func(t *testing.T) {
		id, err := ldap.New(dc.config()).Login(ctx, "alice", "Alice-pw-2026!", remote)
		if err != nil {
			t.Fatal(err)
		}
		if id.Username != "alice@corp.example.com" {
			t.Errorf("username = %q, want alice@corp.example.com", id.Username)
		}
		for _, want := range []string{"linux-users", "linux-admins", "ssh-admins", "CN=ssh-admins," + sambaGroups} {
			if !slices.ContainsFunc(id.Groups, func(g string) bool { return strings.EqualFold(g, want) }) {
				t.Errorf("groups = %v, want %s among them", id.Groups, want)
			}
		}
		if slices.Contains(id.Groups, "ca-admins") {
			t.Errorf("groups = %v: ca-admins is outside group_base_dn", id.Groups)
		}
	})

	t.Run("StartTLS", func(t *testing.T) {
		cfg := dc.config()
		cfg.URL, cfg.StartTLS = dc.ldap, true
		if _, err := ldap.New(cfg).Login(ctx, "alice", "Alice-pw-2026!", remote); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("sAMAccountName as the username", func(t *testing.T) {
		cfg := dc.config()
		cfg.UsernameAttribute = "sAMAccountName"
		id, err := ldap.New(cfg).Login(ctx, "alice", "Alice-pw-2026!", remote)
		if err != nil || id.Username != "alice" {
			t.Errorf("identity %+v, %v; want alice", id, err)
		}
	})

	// What the empty-password check protects against: AD answers
	// "success" to a name with an empty password.
	t.Run("empty password", func(t *testing.T) {
		conn, err := dc.dial()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := conn.UnauthenticatedBind("CN=alice," + sambaUsers); err != nil {
			t.Logf("this directory refuses an empty password by itself: %v", err)
		} else {
			t.Log("as expected, the directory accepts a name with an empty password")
		}
		_, err = ldap.New(dc.config()).Login(ctx, "alice", "", remote)
		if !errors.Is(err, ldap.ErrLoginFailed) {
			t.Errorf("error = %v, want ErrLoginFailed", err)
		}
	})

	refusals := []struct{ name, user, password string }{
		{"wrong password", "alice", "wrong"},
		{"disabled account", "bob", "Bob-pw-2026!"},
		{"unknown user", "mallory", "x"},
		{"wildcard user", "*", "Alice-pw-2026!"},
		{"filter injection", "alice)(objectClass=*", "Alice-pw-2026!"},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			// A new client each time, so the failure limit does not
			// get in the way.
			_, err := ldap.New(dc.config()).Login(ctx, tt.user, tt.password, remote)
			if !errors.Is(err, ldap.ErrLoginFailed) {
				t.Errorf("error = %v, want ErrLoginFailed", err)
			}
		})
	}

	t.Run("wrong service password", func(t *testing.T) {
		cfg := dc.config()
		cfg.BindPassword = "wrong"
		_, err := ldap.New(cfg).Login(ctx, "alice", "Alice-pw-2026!", remote)
		if err == nil || errors.Is(err, ldap.ErrLoginFailed) {
			t.Errorf("error = %v, want a configuration error", err)
		}
	})

	t.Run("unknown certificate", func(t *testing.T) {
		cfg := dc.config()
		cfg.RootCAs = x509.NewCertPool()
		_, err := ldap.New(cfg).Login(ctx, "alice", "Alice-pw-2026!", remote)
		if err == nil || errors.Is(err, ldap.ErrLoginFailed) {
			t.Errorf("error = %v, want a certificate error", err)
		}
	})

	// The control for the next test: the lockout is really on. Five wrong
	// passwords sent to the directory directly lock dave out.
	t.Run("the directory locks accounts", func(t *testing.T) {
		conn, err := dc.dial()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		for range 5 {
			_ = conn.Bind("CN=dave,"+sambaUsers, "wrong")
		}
		if err := conn.Bind("CN=dave,"+sambaUsers, "Dave-pw-2026!"); err == nil {
			t.Fatal("dave is not locked after 5 wrong passwords: the lockout test below would prove nothing")
		}
	})

	// AD locks carol after 5 wrong passwords. Ten wrong ones through the
	// CA must not get her there: the CA stops after 3.
	t.Run("no lockout through the CA", func(t *testing.T) {
		client := ldap.New(dc.config())
		for i := range 10 {
			_, err := client.Login(ctx, "carol", "wrong", remote)
			want := ldap.ErrLoginFailed
			if i >= 3 {
				want = ldap.ErrTooManyFailures
			}
			if !errors.Is(err, want) {
				t.Fatalf("attempt %d: error = %v, want %v", i+1, err, want)
			}
		}
		conn, err := dc.dial()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := conn.Bind("CN=carol,"+sambaUsers, "Carol-pw-2026!"); err != nil {
			t.Errorf("carol was locked out of the directory: %v", err)
		}
	})
}
