// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
	"github.com/bastionxp/bastionxp-ca/internal/keyfile"
	"github.com/bastionxp/bastionxp-ca/internal/store"
	"github.com/bastionxp/bastionxp-ca/internal/token"
)

// "bxp doctor" checks a CA's setup on the CA machine and says what is
// wrong or risky, with a hint for each. It changes nothing.

// doctorTimeout bounds each check over the network.
const doctorTimeout = 5 * time.Second

type level int

const (
	levelOK level = iota
	levelWarn
	levelFail
)

// report collects the results.
type report struct {
	out                 io.Writer
	ok, warnings, fails int
}

func (r *report) add(l level, message, hint string) {
	label := map[level]string{levelOK: "ok  ", levelWarn: "warn", levelFail: "FAIL"}[l]
	fmt.Fprintf(r.out, "  %s  %s\n", label, message)
	if hint != "" {
		fmt.Fprintf(r.out, "        %s\n", hint)
	}
	switch l {
	case levelOK:
		r.ok++
	case levelWarn:
		r.warnings++
	default:
		r.fails++
	}
}

func newDoctorCommand(configPath *string) *cobra.Command {
	var reportPath string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check the CA's setup and say what is wrong",
		Long: "Check the CA on this machine: the configuration, the files and their\n" +
			"permissions, the keys and their passphrase, expiry dates, the database,\n" +
			"whether the server answers, and the identity provider or directory.\n" +
			"It changes nothing and never asks for a passphrase.\n\n" +
			"With --report it also writes a file to attach to a bug report: the\n" +
			"checks, the configuration file, and what the database holds, in counts,\n" +
			"with the ACME proofs that failed recently. It holds no keys, passphrases,\n" +
			"tokens or secrets, and no names of people; it does hold host names,\n" +
			"addresses and paths. Review it before you share it.\n\n" +
			"Exit status 1 if a check failed, so it can run from monitoring.",
		Example: "  bxp doctor --config /etc/bastionxp-ca/bastionxp-ca.yaml\n" +
			"  bxp doctor --config /etc/bastionxp-ca/bastionxp-ca.yaml --report",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			now := time.Now()
			// With --report, everything the checks print goes into the
			// report too.
			var reportText bytes.Buffer
			checksOut := out
			if reportPath != "" {
				writeReportHeader(&reportText, *configPath, now)
				reportSection(&reportText, "Checks (bxp doctor)")
				checksOut = io.MultiWriter(out, &reportText)
			}
			finish := func(cfg *config.Config) error {
				if reportPath == "" {
					return nil
				}
				writeReportRest(cmd.Context(), &reportText, *configPath, cfg, now)
				return writeReportFile(out, reportPath, now, reportText.Bytes())
			}

			fmt.Fprintf(checksOut, "bxp doctor: %s\n\n", *configPath)
			cfg, err := config.Load(*configPath)
			if err != nil {
				r := &report{out: checksOut}
				r.add(levelFail, "the configuration does not load", err.Error())
				if err := finish(nil); err != nil {
					return err
				}
				return errors.New("1 check failed")
			}
			r := runDoctor(cmd.Context(), checksOut, cfg)
			if err := finish(cfg); err != nil {
				return err
			}
			if r.fails > 0 {
				cmd.SilenceUsage = true
				return fmt.Errorf("%d check(s) failed", r.fails)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&reportPath, "report", "",
		"also write a support report, to attach to a bug report; --report alone names it bastionxp-ca-report-<time>.txt")
	cmd.Flags().Lookup("report").NoOptDefVal = reportAuto
	return cmd
}

// reportAuto is the value of a bare --report: a file name with the time.
const reportAuto = "<auto>"

// writeReportFile writes the report, never over an existing file.
func writeReportFile(out io.Writer, path string, now time.Time, content []byte) error {
	if path == reportAuto {
		path = reportName(now)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write the report: %w", err)
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return fmt.Errorf("write the report: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write the report: %w", err)
	}
	fmt.Fprintf(out, "\nReport written to %s. Review it before you share it.\n", path)
	return nil
}

func runDoctor(ctx context.Context, out io.Writer, cfg *config.Config) *report {
	r := &report{out: out}
	r.add(levelOK, "the configuration is valid", "")

	if !checkFiles(r, cfg) {
		fmt.Fprintf(out, "\n%d ok, %d warnings, %d failed\n", r.ok, r.warnings, r.fails)
		return r
	}
	authority := checkKeys(r, cfg)
	if authority != nil {
		checkExpiry(r, authority)
		checkLifetimes(r, cfg, authority)
		checkConstraints(r, cfg, authority)
		for _, kind := range []string{ca.SSHUserCA, ca.SSHHostCA} {
			if next := authority.NextSSHCA(kind); next != nil {
				r.add(levelWarn, "a next SSH "+kind+" CA key waits to be activated: "+ssh.FingerprintSHA256(next),
					"when it is trusted everywhere: bxp new-ssh-ca "+kind+" --activate")
			}
		}
	}
	checkDatabase(ctx, r, cfg)
	checkServer(ctx, r, cfg)
	checkLogins(ctx, r, cfg)

	fmt.Fprintf(out, "\n%d ok, %d warnings, %d failed\n", r.ok, r.warnings, r.fails)
	return r
}

// checkFiles checks that the CA's files are there and private. It returns
// false if there is no CA to check further.
func checkFiles(r *report, cfg *config.Config) bool {
	info, err := os.Stat(cfg.DataDir)
	if err != nil {
		r.add(levelFail, "data_dir "+cfg.DataDir+" cannot be read", err.Error())
		return false
	}
	if waitingForIntermediate(cfg) {
		r.add(levelFail, "the CA waits for its intermediate certificate",
			"have "+filepath.Join(cfg.DataDir, ca.NextIntermediateCSRFile)+" signed by the root's CA, then: bxp new-intermediate --import <certificate>")
		return false
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, ca.RootCertFile)); err != nil {
		r.add(levelFail, "there is no CA in "+cfg.DataDir, "create one with: bxp init --config <file>")
		return false
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, ca.NextIntermediateCSRFile)); err == nil {
		r.add(levelWarn, "a CSR for a new intermediate waits for its certificate",
			"when the root's CA has signed it: bxp new-intermediate --import <certificate>")
	}
	private := runtime.GOOS != "windows"
	if private && info.Mode().Perm()&0o077 != 0 {
		r.add(levelWarn, fmt.Sprintf("data_dir is open to others (mode %o)", info.Mode().Perm()),
			"chmod 700 "+cfg.DataDir)
	}

	missing := 0
	open := []string{}
	for _, file := range []string{ca.IntermediateCertFile, ca.IntermediateKeyFile, ca.SSHUserCAKeyFile,
		ca.SSHHostCAKeyFile, ca.SSHUserCAPubFile, ca.SSHHostCAPubFile, token.KeyFile} {
		info, err := os.Stat(filepath.Join(cfg.DataDir, file))
		if err != nil {
			r.add(levelFail, file+" is missing in data_dir", "restore it from a backup")
			missing++
			continue
		}
		if private && strings.HasSuffix(file, ".key") && info.Mode().Perm()&0o077 != 0 {
			open = append(open, file)
		}
	}
	if len(open) > 0 {
		r.add(levelWarn, "key files are readable by others: "+strings.Join(open, ", "),
			"chmod 600 "+filepath.Join(cfg.DataDir, "*.key"))
	}
	if missing == 0 {
		r.add(levelOK, "all CA files are in "+cfg.DataDir, "")
	}
	return missing == 0
}

// checkKeys checks how the keys are protected, and that they open. It
// returns the CA if they did.
func checkKeys(r *report, cfg *config.Config) *ca.CA {
	rootKey := filepath.Join(cfg.DataDir, ca.RootKeyFile)
	if _, err := os.Stat(rootKey); err == nil {
		r.add(levelWarn, "the root key is in data_dir", "the server does not need it: move "+rootKey+" to offline storage")
	} else {
		r.add(levelOK, "the root key is not in data_dir", "")
	}

	encrypted, err := keyfile.IsEncrypted(filepath.Join(cfg.DataDir, ca.IntermediateKeyFile))
	if err != nil {
		r.add(levelFail, "the intermediate key cannot be read", err.Error())
		return nil
	}
	passphrase, source, err := keyPassphrase(cfg)
	if err != nil {
		r.add(levelFail, "the key passphrase cannot be read", err.Error())
		return nil
	}
	switch {
	case !encrypted && passphrase != nil:
		r.add(levelFail, "a key passphrase is given ("+source+"), but the keys are not encrypted",
			"remove the passphrase setting; the server refuses to start like this")
		return nil
	case !encrypted:
		r.add(levelWarn, "the server's keys are not encrypted", "optional; "+seeDocs)
	case passphrase == nil:
		r.add(levelWarn, "the server's keys are encrypted, but no passphrase is configured",
			"the server will ask on its terminal; under systemd use the credential "+keyCredential)
		return nil
	default:
		r.add(levelOK, "the server's keys are encrypted; passphrase from "+source, "")
		if file := cfg.CA.KeyPassphraseFile; file != "" && sameFilesystem(file, cfg.DataDir) {
			r.add(levelWarn, "ca.key_passphrase_file is on the same disk as data_dir",
				"a copy of the disk holds keys and passphrase; a systemd credential sealed to the TPM is safer")
		}
	}

	authority, err := ca.Load(cfg.DataDir, passphrase)
	if err != nil {
		r.add(levelFail, "the CA keys do not open", err.Error())
		return nil
	}
	// Read the token key without creating it: doctor changes nothing.
	if _, err := keyfile.Read(filepath.Join(cfg.DataDir, token.KeyFile), passphrase); err != nil {
		r.add(levelFail, "the token key does not open", err.Error())
		return nil
	}
	r.add(levelOK, "the keys open, and the intermediate is signed by the root", "")
	return authority
}

func checkExpiry(r *report, authority *ca.CA) {
	now := time.Now()
	for _, c := range []struct {
		name string
		cert *x509.Certificate
		warn time.Duration
		hint string
	}{
		{"root", authority.RootCert(), expiryWarning(authority.RootCert(), rootWarningMax), "a new root means a new CA, trusted anew everywhere: plan it"},
		{"intermediate", authority.IntermediateCert(), expiryWarning(authority.IntermediateCert(), intermediateWarningMax), "replace it with: bxp new-intermediate"},
	} {
		left := c.cert.NotAfter.Sub(now)
		until := c.cert.NotAfter.Format("2006-01-02")
		switch {
		case left <= 0:
			r.add(levelFail, "the "+c.name+" certificate expired on "+until, c.hint)
		case left < c.warn:
			r.add(levelWarn, fmt.Sprintf("the %s certificate expires on %s, in %d days", c.name, until, int(left.Hours()/24)), c.hint)
		default:
			r.add(levelOK, "the "+c.name+" certificate is valid until "+until, "")
		}
	}
}

// checkLifetimes compares the CA certificates' lifetimes with
// ca.root_validity and ca.intermediate_validity, which take effect only
// when a certificate is made: the root at init, the intermediate at init
// and at new-intermediate. Only for a root BastionXP CA made itself: under an
// external root, the root's CA decides.
func checkLifetimes(r *report, cfg *config.Config, authority *ca.CA) {
	root := authority.RootCert()
	if root.Subject.CommonName != cfg.CA.Name+" Root CA" || !slices.Contains(root.Subject.Organization, cfg.CA.Organization) {
		return
	}
	differs := func(cert *x509.Certificate, want time.Duration) bool {
		have := cert.NotAfter.Sub(cert.NotBefore)
		return have-want > 24*time.Hour || want-have > 24*time.Hour
	}
	if cfg.CA.RootValidity != "" && differs(root, cfg.CA.RootLifetime()) {
		r.add(levelWarn, fmt.Sprintf("the root is valid for %s, but ca.root_validity says %s",
			caLifetime(root), cfg.CA.RootValidity),
			"ca.root_validity is used only when the CA is created; it does not change this root")
	}
	if inter := authority.IntermediateCert(); differs(inter, cfg.CA.IntermediateLifetime()) {
		r.add(levelOK, fmt.Sprintf("the intermediate is valid for %s; the next one (bxp new-intermediate) will be for %s",
			caLifetime(inter), lifetimeOf(cfg.CA.IntermediateLifetime())), "")
	}
}

// caLifetime writes a CA certificate's lifetime, in years or days.
func caLifetime(cert *x509.Certificate) string {
	return lifetimeOf(cert.NotAfter.Sub(cert.NotBefore).Round(24 * time.Hour))
}

func lifetimeOf(d time.Duration) string {
	const year = 365 * 24 * time.Hour
	if d%year == 0 {
		return fmt.Sprintf("%dy", d/year)
	}
	return fmt.Sprintf("%dd", d/(24*time.Hour))
}

// checkConstraints shows the intermediate's name constraints, and warns if
// the configuration says otherwise: they change only with a new
// intermediate.
func checkConstraints(r *report, cfg *config.Config, authority *ca.CA) {
	i := authority.IntermediateCert()
	have := slices.DeleteFunc(slices.Clone(i.PermittedDNSDomains), func(d string) bool { return d == "invalid" })
	want := slices.Clone(cfg.CA.NameConstraints.DNSDomains)
	var haveIPs, wantIPs []string
	for _, n := range i.PermittedIPRanges {
		haveIPs = append(haveIPs, n.String())
	}
	for _, n := range cfg.CA.NameConstraints.CA().IPRanges {
		wantIPs = append(wantIPs, n.String())
	}
	for _, list := range [][]string{have, want, haveIPs, wantIPs} {
		slices.Sort(list)
	}
	if !slices.Equal(have, want) || !slices.Equal(haveIPs, wantIPs) {
		r.add(levelWarn, "the name constraints differ between the configuration and the intermediate",
			"they are written into the intermediate: a new one takes them (bxp new-intermediate)")
		return
	}
	if len(have)+len(haveIPs) > 0 {
		r.add(levelOK, "name constraints: "+strings.Join(append(have, haveIPs...), ", "), "")
	}
}

func checkDatabase(ctx context.Context, r *report, cfg *config.Config) {
	path := filepath.Join(cfg.DataDir, store.FileName)
	if _, err := os.Stat(path); err != nil {
		r.add(levelWarn, "there is no database yet", "it is created when the server first starts")
		return
	}
	// Read-only: looking must not update the database under a server
	// of another version that still runs.
	db, err := store.OpenReadOnly(path)
	if err != nil {
		r.add(levelFail, "the database does not open", err.Error())
		return
	}
	defer db.Close()
	if err := db.Check(ctx); err != nil {
		r.add(levelFail, "the database is damaged", err.Error()+"; restore it from a backup")
		return
	}
	version, err := db.Version(ctx)
	if err != nil {
		r.add(levelFail, "the database cannot be read", err.Error())
		return
	}
	switch want := store.SchemaVersion(); {
	case version > want:
		r.add(levelFail, fmt.Sprintf("the database has schema %d, from a newer version (this one knows up to %d)", version, want),
			"use the newer version, or restore the backup from before the upgrade")
		return
	case version < want:
		r.add(levelWarn, fmt.Sprintf("the database has schema %d; this version updates it to %d when the server starts", version, want),
			"back up first (bxp backup), with the version that runs now")
		return
	}
	certs, err := db.Certificates(ctx, false)
	if err != nil {
		r.add(levelFail, "the database cannot be read", err.Error())
		return
	}
	r.add(levelOK, fmt.Sprintf("the database is intact (schema %d, %d certificates)", version, len(certs)), "")
}

// checkServer asks the running server for /health, and the public address
// for the root certificate.
func checkServer(ctx context.Context, r *report, cfg *config.Config) {
	rootPEM, err := os.ReadFile(filepath.Join(cfg.DataDir, ca.RootCertFile))
	if err != nil {
		r.add(levelFail, "root.crt cannot be read", err.Error())
		return
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(rootPEM)
	client := &http.Client{
		Timeout:   doctorTimeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}},
		// A redirect would mean somebody else answers.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	address := serverAddress(cfg)
	if body, err := get(ctx, client, address+"/health"); err != nil {
		r.add(levelWarn, "the server does not answer at "+address, err.Error()+" (not running yet?)")
	} else if !strings.Contains(string(body), `"ok"`) {
		r.add(levelFail, "something else answers at "+address, "check server.address and server.url")
	} else {
		r.add(levelOK, "the server answers at "+address, "")
	}

	if cfg.Server.PublicURL != "" {
		body, err := get(ctx, client, cfg.Server.PublicURL+ca.RootCertPath)
		switch {
		case err != nil:
			r.add(levelWarn, "the public address does not answer: "+cfg.Server.PublicURL, err.Error())
		case !bytes.Equal(bytes.TrimSpace(body), bytes.TrimSpace(rootPEM)):
			r.add(levelFail, "the public address serves another root certificate: "+cfg.Server.PublicURL,
				"server.public_url points somewhere else")
		default:
			r.add(levelOK, "the public address serves this CA's root: "+cfg.Server.PublicURL, "")
		}
	}
}

// serverAddress is where the server should answer: server.url, or the
// listening address on this machine.
func serverAddress(cfg *config.Config) string {
	if cfg.Server.URL != "" {
		return strings.TrimRight(cfg.Server.URL, "/")
	}
	host, port, err := net.SplitHostPort(cfg.Server.Address)
	if err != nil {
		return "https://localhost:8443"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		// A name the server's certificate has, if it has one for here.
		host = "localhost"
		for _, name := range []string{"localhost", "127.0.0.1"} {
			if slices.Contains(cfg.Server.Names, name) {
				host = name
				break
			}
		}
	}
	return "https://" + net.JoinHostPort(host, port)
}

func get(ctx context.Context, client *http.Client, address string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}
	return body, nil
}

func checkLogins(ctx context.Context, r *report, cfg *config.Config) {
	if cfg.OIDC.Issuer != "" {
		client, err := newOIDCClient(cfg.OIDC)
		if err == nil {
			ctx, cancel := context.WithTimeout(ctx, doctorTimeout)
			err = client.Check(ctx)
			cancel()
		}
		if err != nil {
			r.add(levelFail, "the identity provider cannot be reached", err.Error())
		} else {
			r.add(levelOK, "the identity provider answers: "+cfg.OIDC.Issuer, "")
		}
	}
	if cfg.LDAP.Enabled() {
		client, err := newLDAPClient(cfg.LDAP)
		if err != nil {
			r.add(levelFail, "the ldap settings cannot be used", err.Error())
			return
		}
		ctx, cancel := context.WithTimeout(ctx, doctorTimeout)
		err = client.Check(ctx)
		cancel()
		if err != nil {
			r.add(levelFail, "the directory does not accept the CA", err.Error())
		} else {
			r.add(levelOK, "the directory accepts the CA's service account: "+cfg.LDAP.URL, "")
		}
	}
}
