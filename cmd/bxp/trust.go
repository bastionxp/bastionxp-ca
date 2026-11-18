// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/client"
	"github.com/bastionxp/bastionxp-ca/internal/server"
)

// "bxp trust" is the first thing a client runs. It fetches the CA's
// root certificate, checks it against a fingerprint the person got from
// the administrator by some other way, and saves it, together with the
// CA's address, for the other commands.

const (
	// envClientDir moves the saved trust somewhere else. Tests use it.
	envClientDir = "BXP_CLIENT_DIR"

	trustFile     = "client.yaml"
	trustRootFile = "root.crt"

	// maxDownloadBytes limits what is read from the CA. A root
	// certificate is about one kilobyte.
	maxDownloadBytes = 64 * 1024
)

// savedTrust is what "bxp trust" saves.
type savedTrust struct {
	// URL is the CA's address, without a trailing slash.
	URL string `yaml:"url"`
	// Fingerprint is the SHA-256 fingerprint of the root, as checked.
	Fingerprint string `yaml:"fingerprint"`
	// RootFile is where the root certificate is. It is not in the file:
	// it is always next to it.
	RootFile string `yaml:"-"`
}

// clientDir returns the directory for the saved trust: BXP_CLIENT_DIR,
// or "bastionxp-ca" in the user's configuration directory.
func clientDir() (string, error) {
	if dir := os.Getenv(envClientDir); dir != "" {
		return dir, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot find your configuration directory, set %s: %w", envClientDir, err)
	}
	return filepath.Join(dir, "bastionxp-ca"), nil
}

// loadTrust returns what "bxp trust" saved, or nil if it never ran.
func loadTrust() (*savedTrust, error) {
	dir, err := clientDir()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, trustFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var saved savedTrust
	if err := yaml.Unmarshal(data, &saved); err != nil || saved.URL == "" {
		return nil, fmt.Errorf("%s is damaged: run \"bxp trust\" again", filepath.Join(dir, trustFile))
	}
	saved.RootFile = filepath.Join(dir, trustRootFile)
	return &saved, nil
}

// trustOptions are the settings of "bxp trust".
type trustOptions struct {
	url         string
	fingerprint string
	ssh         bool   // also trust the CA's SSH host certificates
	knownHosts  string // where to write that; empty: ~/.ssh/known_hosts
	force       bool   // replace what is saved for another CA
}

func newTrustCommand() *cobra.Command {
	var opts trustOptions

	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Trust a BastionXP CA server: the first step on every client",
		Long: "Fetch the CA's root certificate, check it against its fingerprint, and\n" +
			"save it together with the CA's address. Afterwards the other commands\n" +
			"need neither --ca-url nor --root.\n\n" +
			"Get the fingerprint from the CA's administrator, by any other way than\n" +
			"the CA server itself: a message, a wiki page. \"bxp init\" printed it,\n" +
			"and the server's log has it. It is what makes the root you fetch the\n" +
			"right one, so it cannot be left out.\n\n" +
			"With --ssh, ssh is also told to trust host certificates from this CA.",
		Example: "  bxp trust --ca-url https://ca.example.com:8443 \\\n" +
			"      --fingerprint 9d4b7c0e...e1f0\n\n" +
			"  bxp trust --ca-url https://ca.example.com:8443 --fingerprint 9d4b... --ssh",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTrust(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.url, "ca-url", os.Getenv(envURL),
		"address of the CA server, e.g. https://ca.example.com:8443 (or "+envURL+")")
	cmd.Flags().StringVar(&opts.fingerprint, "fingerprint", "",
		"SHA-256 fingerprint of the CA's root certificate, from the administrator")
	cmd.Flags().BoolVar(&opts.ssh, "ssh", false,
		"also add the CA's SSH host key to known_hosts, so ssh trusts hosts with its certificates")
	cmd.Flags().StringVar(&opts.knownHosts, "known-hosts", "", "the known_hosts file for --ssh (default: ~/.ssh/known_hosts)")
	cmd.Flags().BoolVar(&opts.force, "force", false, "replace the trust saved for another CA")
	return cmd
}

func runTrust(ctx context.Context, out io.Writer, opts trustOptions) error {
	baseURL, err := checkCAURL(opts.url)
	if err != nil {
		return err
	}
	want, err := normalizeFingerprint(opts.fingerprint)
	if err != nil {
		return err
	}
	dir, err := clientDir()
	if err != nil {
		return err
	}

	// Never replace the trust in one CA with another without being told.
	saved, err := loadTrust()
	if err != nil {
		return err
	}
	if saved != nil && (saved.URL != baseURL || saved.Fingerprint != want) && !opts.force {
		return fmt.Errorf("this machine already trusts the CA at %s: use --force to trust %s instead", saved.URL, baseURL)
	}

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	// 1. Fetch the root. Nothing can be checked yet, because nothing is
	// trusted yet. That is what the fingerprint is for.
	unchecked := &http.Client{Transport: &http.Transport{
		// The certificate is checked by its fingerprint below.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	}}
	rootPEM, err := download(ctx, unchecked, baseURL+ca.RootCertPath)
	if err != nil {
		return err
	}
	root, err := parseRoot(rootPEM)
	if err != nil {
		return err
	}

	// 2. Is it the root the administrator meant?
	got := ca.CertFingerprint(root)
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return fmt.Errorf("the root certificate at %s does NOT have the fingerprint you gave.\n"+
			"  expected: %s\n  received: %s\n"+
			"Do not use this CA. Check the address and the fingerprint with the administrator;\n"+
			"if both are right, someone may be intercepting the connection", baseURL, want, got)
	}

	// 3. Is the server one of this CA? A server that only hands out a
	// copy of the root, which is public, fails here.
	pool := x509.NewCertPool()
	pool.AddCert(root)
	checked := client.HTTPClientFor(pool)
	if _, err := download(ctx, checked, baseURL+"/health"); err != nil {
		return fmt.Errorf("the root is right, but the server at %s does not have a certificate from it: %w", baseURL, err)
	}

	// 4. Save both.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	rootFile := filepath.Join(dir, trustRootFile)
	if err := os.WriteFile(rootFile, ca.EncodeCertPEM(root), 0o644); err != nil {
		return err
	}
	data, err := yaml.Marshal(savedTrust{URL: baseURL, Fingerprint: want})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, trustFile), data, 0o644); err != nil {
		return err
	}

	fmt.Fprintf(out, "Trusted:      %s\n", baseURL)
	fmt.Fprintf(out, "Root:         %s\n", root.Subject.CommonName)
	fmt.Fprintf(out, "SHA-256:      %s\n", got)
	fmt.Fprintf(out, "Saved in:     %s\n", dir)

	// 5. ssh, if asked. The key comes over the checked connection.
	if opts.ssh {
		path, added, err := trustSSHHosts(ctx, checked, baseURL, opts.knownHosts)
		if err != nil {
			return err
		}
		if added {
			fmt.Fprintf(out, "SSH:          host certificates from this CA are trusted (%s)\n", path)
		} else {
			fmt.Fprintf(out, "SSH:          already trusted in %s\n", path)
		}
	}

	fmt.Fprintln(out, "\nThe bxp commands use this from now on. Other programs on this machine")
	fmt.Fprintln(out, "do not; to make the whole system trust the CA, run:")
	fmt.Fprintf(out, "  %s\n", systemTrustCommand(rootFile))
	return nil
}

// checkCAURL checks the CA's address and returns it without a trailing slash.
func checkCAURL(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("give the CA server's address with --ca-url or %s", envURL)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" {
		return "", fmt.Errorf("invalid server URL %q: use a form like https://ca.example.com:8443", raw)
	}
	return strings.TrimRight(raw, "/"), nil
}

// normalizeFingerprint accepts a SHA-256 fingerprint the way people paste
// it: plain hex as "bxp init" prints it, or with colons and in upper
// case as openssl prints it, with or without a "SHA256:" in front.
func normalizeFingerprint(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("give the root's fingerprint with --fingerprint. Trusting a CA without it would trust " +
			"whoever answers at that address; get it from the CA's administrator")
	}
	text := strings.ToLower(strings.TrimSpace(raw))
	text = strings.TrimPrefix(strings.TrimPrefix(text, "sha256:"), "sha256 fingerprint=")
	text = strings.NewReplacer(":", "", " ", "").Replace(text)
	if len(text) != 64 || strings.Trim(text, "0123456789abcdef") != "" {
		return "", fmt.Errorf("%q is not a SHA-256 fingerprint: it must have 64 hex digits", raw)
	}
	return text, nil
}

// download fetches an address and returns the body.
func download(ctx context.Context, httpClient *http.Client, address string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the CA server: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered with status %s", address, resp.Status)
	}
	return body, nil
}

// parseRoot reads exactly one CA certificate in PEM form.
func parseRoot(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("the server did not send one root certificate: is this a BastionXP CA server?")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot read the root certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("the certificate the server sent is not a CA certificate")
	}
	return cert, nil
}

// trustSSHHosts adds the CA's SSH host key to known_hosts. It reports
// false if the line was there already.
func trustSSHHosts(ctx context.Context, checked *http.Client, baseURL, path string) (string, bool, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", false, err
		}
		path = filepath.Join(home, ".ssh", "known_hosts")
	}
	data, err := download(ctx, checked, baseURL+server.SSHHostCAPath)
	if err != nil {
		return "", false, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return "", false, fmt.Errorf("cannot read the CA's SSH host key: %w", err)
	}
	keyText := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))

	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	for _, line := range strings.Split(string(existing), "\n") {
		if strings.HasPrefix(line, "@cert-authority ") && strings.Contains(line, keyText) {
			return path, false, nil
		}
	}

	// "*": any host. ssh still checks that the host's certificate names
	// the host it connects to.
	line := "@cert-authority * " + keyText + " bastionxp-ca " + baseURL + "\n"
	if len(existing) > 0 && !bytes.HasSuffix(existing, []byte("\n")) {
		line = "\n" + line
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", false, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return "", false, err
	}
	if _, err := f.WriteString(line); err != nil {
		f.Close()
		return "", false, err
	}
	return path, true, f.Close()
}

// systemTrustCommand returns the command that installs the root for the
// whole system. It is only printed: it needs admin rights and changes
// what every program on the machine trusts.
func systemTrustCommand(rootFile string) string {
	switch runtime.GOOS {
	case "darwin":
		return "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain " + rootFile
	case "windows":
		return "certutil -addstore -f Root " + rootFile
	default:
		return "sudo cp " + rootFile + " /usr/local/share/ca-certificates/bastionxp-ca.crt && sudo update-ca-certificates" +
			"   (Debian, Ubuntu; elsewhere see your system's documentation)"
	}
}
