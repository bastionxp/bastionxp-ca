// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme"

	caacme "github.com/bastionxp/bastionxp-ca/internal/acme"
	"github.com/bastionxp/bastionxp-ca/internal/client"
)

// acmeTimeout is how long the whole exchange with the CA may take.
const acmeTimeout = 2 * time.Minute

// accountKeyFile is the name of the ACME account key file, next to the
// certificates.
const accountKeyFile = "acme-account.key"

// acmeAccount says where the ACME account is: which CA, and which key.
type acmeAccount struct {
	directory  string // ACME directory address; empty: the BastionXP CA server's
	accountKey string // file with the account key
}

// acmeOptions are the settings of "bxp acme issue".
type acmeOptions struct {
	names       []string // host names for the certificate
	outDir      string   // where the key and certificate files go
	force       bool     // replace existing files
	challenge   string   // "http-01" or "tls-alpn-01"
	httpAddress string   // where to answer http-01
	tlsAddress  string   // where to answer tls-alpn-01
	accountKey  string   // file with the ACME account key
	directory   string   // ACME directory address; empty: the BastionXP CA server's
}

// acmeRenewOptions are the settings of "bxp acme renew".
type acmeRenewOptions struct {
	cert        string // the certificate to renew
	key         string // its private key
	force       bool   // renew even if it is not time yet
	exec        string // a command to run after a renewal
	challenge   string
	httpAddress string
	tlsAddress  string
	accountKey  string
	directory   string
}

// acmeRevokeOptions are the settings of "bxp acme revoke".
type acmeRevokeOptions struct {
	cert       string // the certificate to revoke
	key        string // its private key, to sign with instead of the account key
	reason     string
	accountKey string
	directory  string
}

func newACMECommand() *cobra.Command {
	var conn connection
	var directory string

	cmd := &cobra.Command{
		Use:   "acme",
		Short: "Get and manage TLS certificates with ACME: no token, no login",
		Long: "Get TLS certificates with the ACME protocol, from this CA or from any\n" +
			"other ACME CA (--directory). Nobody has to hand out a token or log in:\n" +
			"the machine proves that the host names are its own.\n\n" +
			"  issue         get a certificate\n" +
			"  renew         get a new one for the names of a certificate, when it is due\n" +
			"  revoke        tell the CA a certificate must no longer be trusted\n" +
			"  rollover-key  replace the account key\n" +
			"  deactivate    close the account for good\n\n" +
			"The account is just a key, acme-account.key, made by the first \"issue\".\n" +
			"Keep it: renewals and revocations use it again.",
		Example: "  sudo bxp acme issue --ca-url https://ca.example.com:8443 --root root.crt \\\n" +
			"      --name web.example.com\n" +
			"  sudo bxp acme renew --cert web.example.com.crt --key web.example.com.key \\\n" +
			"      --exec \"systemctl reload nginx\"",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}
	// ACME needs no token and no login: the machine proves itself.
	addConnectionFlags(cmd, &conn, false)
	cmd.PersistentFlags().StringVar(&directory, "directory", "",
		"address of the ACME directory of another CA, e.g. https://acme-v02.api.letsencrypt.org/directory\n"+
			"(default: the one of the server given with --ca-url). The CA's certificate is\n"+
			"checked against --root, or against the system's roots")
	saved := cmd.PersistentPreRunE
	cmd.PersistentPreRunE = func(c *cobra.Command, args []string) error {
		if directory != "" {
			// Another CA: the root saved by "bxp trust" is not its root.
			conn.prompt = c.ErrOrStderr()
			return nil
		}
		return saved(c, args)
	}
	account := func() acmeAccount { return acmeAccount{directory: directory} }

	cmd.AddCommand(
		newACMEIssueCommand(&conn, &directory),
		newACMERenewCommand(&conn, &directory),
		newACMERevokeCommand(&conn, &directory),
		newACMERolloverCommand(&conn, account),
		newACMEDeactivateCommand(&conn, account),
	)
	// A CA's rate limit is said plainly, with when to try again.
	for _, sub := range cmd.Commands() {
		run := sub.RunE
		sub.RunE = func(c *cobra.Command, args []string) error { return explainACMEError(run(c, args)) }
	}
	return cmd
}

// addChallengeFlags adds the flags that choose how names are proved.
func addChallengeFlags(cmd *cobra.Command, challenge, httpAddress, tlsAddress *string) {
	cmd.Flags().StringVar(challenge, "challenge", "http-01",
		"how to prove the names: http-01 (port 80) or tls-alpn-01 (port 443)")
	cmd.Flags().StringVar(httpAddress, "http-address", ":80",
		"where to listen for http-01. The CA always asks on port 80,\n"+
			"so another port only works if something forwards port 80 to it")
	cmd.Flags().StringVar(tlsAddress, "tls-address", ":443",
		"where to listen for tls-alpn-01. The CA always connects to port 443,\n"+
			"so another port only works if something forwards port 443 to it")
}

func newACMEIssueCommand(conn *connection, directory *string) *cobra.Command {
	var opts acmeOptions
	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Get a TLS certificate",
		Long: "Get a TLS certificate for this machine.\n\n" +
			"How the proof works: the CA connects to each host name, and this\n" +
			"command answers. With --challenge http-01 (the default) the CA sends\n" +
			"an HTTP request to port 80; with tls-alpn-01 it opens a TLS connection\n" +
			"to port 443. So run it on the machine the names point to, with that\n" +
			"port free and reachable from the CA. Ports below 1024 usually need root.\n" +
			"(dns-01, which wildcard names need, is answered in your DNS: use an\n" +
			"ACME client with a plugin for your DNS provider, such as lego or certbot.)\n\n" +
			"The CA only issues for names in the domains its administrator has\n" +
			"allowed. It writes the same files as \"bxp tls\":\n\n" +
			"  <name>.key   the private key (it never leaves this machine)\n" +
			"  <name>.crt   the certificate, followed by the intermediate certificate\n\n" +
			"It also keeps an account key (acme-account.key). Keep that file: the\n" +
			"next request uses it again.",
		Example: "  sudo bxp acme issue --ca-url https://ca.example.com:8443 --root root.crt \\\n" +
			"      --name web.example.com",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.directory = *directory
			return runACME(cmd.Context(), cmd.OutOrStdout(), *conn, opts)
		},
	}
	cmd.Flags().StringArrayVar(&opts.names, "name", nil, "a host name or IP address for the certificate (repeat for more)")
	cmd.Flags().StringVar(&opts.outDir, "out-dir", ".", "directory to write the key and certificate to")
	cmd.Flags().BoolVar(&opts.force, "force", false, "replace the key and certificate files if they exist")
	addChallengeFlags(cmd, &opts.challenge, &opts.httpAddress, &opts.tlsAddress)
	cmd.Flags().StringVar(&opts.accountKey, "account-key", "",
		"file with the ACME account key; created if missing (default: "+accountKeyFile+" in --out-dir)")
	return cmd
}

func newACMERenewCommand(conn *connection, directory *string) *cobra.Command {
	var opts acmeRenewOptions
	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Get a new certificate for the names of one that is due",
		Long: "Get a new certificate for the same names as an existing one, proving\n" +
			"the names again as \"bxp acme issue\" does.\n\n" +
			"It asks the CA when to renew (ACME Renewal Information, RFC 9773):\n" +
			"BastionXP CA says when a third of the lifetime is left, or at once for a\n" +
			"revoked certificate. A CA that does not say: when a third is left. So\n" +
			"run it every hour from a timer: it renews at the right moment by itself\n" +
			"(BastionXP CA's certificates last 24 hours by default, so daily is not\n" +
			"often enough). A certificate that has expired is renewed too.\n\n" +
			"A new key is made, of the same kind as the old one, and the key and\n" +
			"certificate files are replaced (keeping their owner and permissions).",
		Example: "  sudo bxp acme renew --cert web.example.com.crt --key web.example.com.key \\\n" +
			"      --exec \"systemctl reload nginx\"",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.directory = *directory
			return runACMERenew(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), *conn, opts)
		},
	}
	cmd.Flags().StringVar(&opts.cert, "cert", "", "the certificate to renew")
	cmd.Flags().StringVar(&opts.key, "key", "", "its private key")
	cmd.Flags().BoolVar(&opts.force, "force", false, "renew now, whatever the CA suggests")
	cmd.Flags().StringVar(&opts.exec, "exec", "", "a command to run after a renewal, e.g. \"systemctl reload nginx\"")
	addChallengeFlags(cmd, &opts.challenge, &opts.httpAddress, &opts.tlsAddress)
	cmd.Flags().StringVar(&opts.accountKey, "account-key", "",
		"file with the ACME account key; created if missing (default: "+accountKeyFile+" next to --cert)")
	return cmd
}

func newACMERevokeCommand(conn *connection, directory *string) *cobra.Command {
	var opts acmeRevokeOptions
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a certificate",
		Long: "Ask the CA to revoke a certificate it issued over ACME.\n\n" +
			"The request is signed with the account key that got the certificate,\n" +
			"or, with --key, with the certificate's own key: that works without the\n" +
			"account, for instance after the account key was lost.\n\n" +
			"Reasons: " + reasonNames() + ".\n\n" +
			"The CA's list of revoked certificates (CRL) and OCSP show it at once.\n" +
			"An administrator can do the same with \"bxp revoke\".",
		Example: "  bxp acme revoke --cert web.example.com.crt --reason superseded\n" +
			"  bxp acme revoke --cert web.example.com.crt --key web.example.com.key \\\n" +
			"      --reason key-compromise",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.directory = *directory
			return runACMERevoke(cmd.Context(), cmd.OutOrStdout(), *conn, opts)
		},
	}
	cmd.Flags().StringVar(&opts.cert, "cert", "", "the certificate to revoke")
	cmd.Flags().StringVar(&opts.key, "key", "", "sign with the certificate's private key instead of the account key")
	cmd.Flags().StringVar(&opts.reason, "reason", "unspecified", "why: "+reasonNames())
	cmd.Flags().StringVar(&opts.accountKey, "account-key", "",
		"file with the ACME account key (default: "+accountKeyFile+" next to --cert)")
	return cmd
}

func newACMERolloverCommand(conn *connection, account func() acmeAccount) *cobra.Command {
	var accountKey string
	cmd := &cobra.Command{
		Use:   "rollover-key",
		Short: "Replace the ACME account key",
		Long: "Replace the account key with a new one, for instance when the old one\n" +
			"may have been seen by others. The account stays the same; only its key\n" +
			"changes. The new key is saved first as <file>.new, and takes the old\n" +
			"one's place once the CA has accepted it.",
		Example: "  bxp acme rollover-key --account-key /etc/bastionxp-ca/acme-account.key",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			a := account()
			a.accountKey = accountKey
			return runACMERollover(cmd.Context(), cmd.OutOrStdout(), *conn, a)
		},
	}
	cmd.Flags().StringVar(&accountKey, "account-key", accountKeyFile, "file with the ACME account key")
	return cmd
}

func newACMEDeactivateCommand(conn *connection, account func() acmeAccount) *cobra.Command {
	var accountKey string
	var yes bool
	cmd := &cobra.Command{
		Use:   "deactivate",
		Short: "Close the ACME account for good",
		Long: "Close the ACME account. This cannot be undone: the CA no longer\n" +
			"accepts anything signed with its key. Certificates already issued stay\n" +
			"valid, and their own keys can still revoke them. To get certificates\n" +
			"again, \"bxp acme issue\" with a new account key.",
		Example: "  bxp acme deactivate --account-key /etc/bastionxp-ca/acme-account.key",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			a := account()
			a.accountKey = accountKey
			var confirm func(string) (bool, error)
			if !yes {
				confirm = terminalConfirm(cmd.ErrOrStderr())
				if confirm == nil {
					return errors.New("closing the account cannot be undone: give --yes")
				}
			}
			return runACMEDeactivate(cmd.Context(), cmd.OutOrStdout(), *conn, a, confirm)
		},
	}
	cmd.Flags().StringVar(&accountKey, "account-key", accountKeyFile, "file with the ACME account key")
	cmd.Flags().BoolVar(&yes, "yes", false, "close the account without asking")
	return cmd
}

// newACMEClient returns an ACME client for the account with key.
func newACMEClient(conn connection, directory string, key crypto.Signer) (*acme.Client, error) {
	directory, err := acmeDirectoryURL(conn, directory)
	if err != nil {
		return nil, err
	}
	httpClient, err := client.NewHTTPClient(conn.root)
	if err != nil {
		return nil, err
	}
	return &acme.Client{Key: key, DirectoryURL: directory, HTTPClient: httpClient, RetryBackoff: acmeRetry}, nil
}

// checkChallenge checks the --challenge value: one this command can answer.
func checkChallenge(kind string) (string, error) {
	switch kind {
	case "":
		return "http-01", nil
	case "http-01", "tls-alpn-01":
		return kind, nil
	}
	return "", fmt.Errorf("--challenge must be http-01 or tls-alpn-01, got %q", kind)
}

// startResponder starts answering the CA's challenge requests.
func startResponder(kind, httpAddress, tlsAddress string) (challengeAnswerer, error) {
	if kind == "tls-alpn-01" {
		return startALPNResponder(tlsAddress)
	}
	return startChallengeResponder(httpAddress)
}

// obtainCertificate gets a certificate for names and the key's public
// key: it registers (harmless if the account exists), orders, proves
// each name and sends the CSR. It returns the chain, leaf first.
func obtainCertificate(ctx context.Context, acmeClient *acme.Client, responder challengeAnswerer, kind string, names []string, key crypto.Signer) ([][]byte, error) {
	// 1. The account. It is only the key: registering again is harmless.
	_, err := acmeClient.Register(ctx, &acme.Account{}, acme.AcceptTOS)
	if err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("cannot register with the CA: %w", err)
	}

	// 2. The order.
	var ids []acme.AuthzID
	for _, name := range names {
		if net.ParseIP(name) != nil {
			ids = append(ids, acme.AuthzID{Type: "ip", Value: name})
		} else {
			ids = append(ids, acme.AuthzID{Type: "dns", Value: name})
		}
	}
	order, err := acmeClient.AuthorizeOrder(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("the CA refused the order: %w", err)
	}

	// 3 and 4. Prove each name: put the answer in place, tell the CA,
	// and wait for its verdict.
	for _, authzURL := range order.AuthzURLs {
		authz, err := acmeClient.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, err
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		name := authz.Identifier.Value
		challenge := findChallenge(authz, kind)
		if challenge == nil {
			if authz.Wildcard {
				return nil, fmt.Errorf("*.%s can only be proved with dns-01, in your DNS: use an ACME client with a plugin for your DNS provider", name)
			}
			return nil, fmt.Errorf("the CA offers no %s challenge for %s", kind, name)
		}
		if err := responder.prepare(acmeClient, challenge, name); err != nil {
			return nil, err
		}

		if _, err := acmeClient.Accept(ctx, challenge); err != nil {
			return nil, fmt.Errorf("proving %s: %w", name, err)
		}
		if _, err := acmeClient.WaitAuthorization(ctx, authzURL); err != nil {
			return nil, fmt.Errorf("the CA could not confirm that this machine is %s: %w\n"+
				"Check that %s points to this machine and that the CA can reach port %s here", name, err, name, map[string]string{"http-01": "80", "tls-alpn-01": "443"}[kind])
		}
	}
	if _, err := acmeClient.WaitOrder(ctx, order.URI); err != nil {
		return nil, err
	}

	// 5. The key stays here. The CA gets the CSR.
	csrTemplate := &x509.CertificateRequest{}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			csrTemplate.IPAddresses = append(csrTemplate.IPAddresses, ip)
		} else {
			csrTemplate.DNSNames = append(csrTemplate.DNSNames, name)
		}
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		return nil, err
	}
	chain, _, err := acmeClient.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("the CA did not issue the certificate: %w", err)
	}
	return chain, nil
}

func chainToPEM(chain [][]byte) []byte {
	var out []byte
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}

func runACME(ctx context.Context, out io.Writer, conn connection, opts acmeOptions) error {
	if len(opts.names) == 0 {
		return errors.New("give at least one host name with --name")
	}
	kind, err := checkChallenge(opts.challenge)
	if err != nil {
		return err
	}
	keyFile := filepath.Join(opts.outDir, opts.names[0]+".key")
	certFile := filepath.Join(opts.outDir, opts.names[0]+".crt")
	if !opts.force {
		for _, file := range []string{keyFile, certFile} {
			if _, err := os.Stat(file); err == nil {
				return fmt.Errorf("%s already exists: use --force to replace it, or \"bxp acme renew\"", file)
			}
		}
	}
	if opts.accountKey == "" {
		opts.accountKey = filepath.Join(opts.outDir, accountKeyFile)
	}
	accountKey, err := loadOrCreateAccountKey(opts.accountKey)
	if err != nil {
		return fmt.Errorf("ACME account key: %w", err)
	}
	acmeClient, err := newACMEClient(conn, opts.directory, accountKey)
	if err != nil {
		return err
	}

	// Start listening before asking the CA for anything, so that a port
	// that is taken or forbidden is noticed first.
	responder, err := startResponder(kind, opts.httpAddress, opts.tlsAddress)
	if err != nil {
		return err
	}
	defer responder.stop()

	ctx, cancel := context.WithTimeout(ctx, acmeTimeout)
	defer cancel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	chain, err := obtainCertificate(ctx, acmeClient, responder, kind, opts.names, key)
	if err != nil {
		return err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writePrivateFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		return err
	}
	chainPEM := chainToPEM(chain)
	if err := os.WriteFile(certFile, chainPEM, 0o644); err != nil {
		return err
	}

	fmt.Fprintf(out, "Private key:  %s\n", keyFile)
	fmt.Fprintf(out, "Certificate:  %s\n", certFile)
	if notAfter, err := certNotAfter(string(chainPEM)); err == nil {
		fmt.Fprintf(out, "Valid until:  %s\n", notAfter.Local().Format("2006-01-02 15:04 MST"))
	}
	return nil
}

// readLeaf reads the first certificate of a PEM file.
func readLeaf(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no PEM certificate found", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	return cert, nil
}

// certNames returns the DNS names and IP addresses of a certificate.
func certNames(cert *x509.Certificate) []string {
	names := slices.Clone(cert.DNSNames)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	return names
}

func runACMERenew(ctx context.Context, out, errOut io.Writer, conn connection, opts acmeRenewOptions) error {
	if opts.cert == "" || opts.key == "" {
		return errors.New("give the certificate with --cert and its private key with --key")
	}
	kind, err := checkChallenge(opts.challenge)
	if err != nil {
		return err
	}
	old, err := readLeaf(opts.cert)
	if err != nil {
		return err
	}
	names := certNames(old)
	if len(names) == 0 {
		return fmt.Errorf("%s has no DNS names or IP addresses to renew it for", opts.cert)
	}
	// An expired certificate is no obstacle: ACME proves the names afresh.
	if !opts.force {
		if due, notYet := acmeRenewalDue(ctx, conn, opts.directory, old, time.Now()); !due {
			fmt.Fprintf(out, "Not yet:      %s\n", notYet)
			return nil
		}
	}
	oldKey, err := readPrivateKey(opts.key)
	if err != nil {
		return err
	}
	if !sameKey(oldKey.Public(), old.PublicKey) {
		return fmt.Errorf("%s is not the key of %s", opts.key, opts.cert)
	}
	if err := checkReplaceable(opts.key, opts.cert); err != nil {
		return err
	}
	if opts.accountKey == "" {
		opts.accountKey = filepath.Join(filepath.Dir(opts.cert), accountKeyFile)
	}
	accountKey, err := loadOrCreateAccountKey(opts.accountKey)
	if err != nil {
		return fmt.Errorf("ACME account key: %w", err)
	}
	acmeClient, err := newACMEClient(conn, opts.directory, accountKey)
	if err != nil {
		return err
	}
	responder, err := startResponder(kind, opts.httpAddress, opts.tlsAddress)
	if err != nil {
		return err
	}
	defer responder.stop()

	ctx, cancel := context.WithTimeout(ctx, acmeTimeout)
	defer cancel()
	newKey, err := newKeyLike(oldKey)
	if err != nil {
		return err
	}
	chain, err := obtainCertificate(ctx, acmeClient, responder, kind, names, newKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(newKey)
	if err != nil {
		return err
	}
	// The key first, as "bxp renew" does.
	if err := replaceFile(opts.key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	chainPEM := chainToPEM(chain)
	if err := replaceFile(opts.cert, chainPEM, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "Renewed:      %s (%s)\n", opts.cert, strings.Join(names, ", "))
	if notAfter, err := certNotAfter(string(chainPEM)); err == nil {
		fmt.Fprintf(out, "Valid until:  %s\n", notAfter.Local().Format("2006-01-02 15:04 MST"))
	}
	if opts.exec == "" {
		return nil
	}
	fmt.Fprintf(out, "Running:      %s\n", opts.exec)
	if err := runShell(ctx, opts.exec, out, errOut); err != nil {
		return fmt.Errorf("the certificate was renewed, but %q failed: %w", opts.exec, err)
	}
	return nil
}

func runACMERevoke(ctx context.Context, out io.Writer, conn connection, opts acmeRevokeOptions) error {
	if opts.cert == "" {
		return errors.New("give the certificate to revoke with --cert")
	}
	if opts.reason == "" {
		opts.reason = "unspecified"
	}
	reason, ok := revocationReasons[opts.reason]
	if !ok {
		return fmt.Errorf("unknown reason %q: choose one of %s", opts.reason, reasonNames())
	}
	cert, err := readLeaf(opts.cert)
	if err != nil {
		return err
	}

	// Signed by the certificate's key, or by the account's.
	var certKey crypto.Signer
	var accountKey crypto.Signer
	if opts.key != "" {
		if certKey, err = readPrivateKey(opts.key); err != nil {
			return err
		}
		if !sameKey(certKey.Public(), cert.PublicKey) {
			return fmt.Errorf("%s is not the key of %s", opts.key, opts.cert)
		}
	} else {
		if opts.accountKey == "" {
			opts.accountKey = filepath.Join(filepath.Dir(opts.cert), accountKeyFile)
		}
		if accountKey, err = readAccountKey(opts.accountKey); err != nil {
			return fmt.Errorf("%w\nOr sign with the certificate's own key: --key", err)
		}
	}
	acmeClient, err := newACMEClient(conn, opts.directory, accountKey)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, acmeTimeout)
	defer cancel()
	dir, err := acmeClient.Discover(ctx)
	if err != nil {
		return fmt.Errorf("cannot reach the ACME directory: %w", err)
	}
	if dir.RevokeURL == "" {
		return errors.New("this CA does not revoke certificates over ACME: ask its administrator\n" +
			"(the serial number is " + serialHex(cert) + ")")
	}
	if err := acmeClient.RevokeCert(ctx, certKey, cert.Raw, acme.CRLReasonCode(reason)); err != nil {
		return fmt.Errorf("the CA did not revoke the certificate: %w", err)
	}
	fmt.Fprintf(out, "Revoked:      %s (serial %s, %s)\n", opts.cert, serialHex(cert), opts.reason)
	return nil
}

func serialHex(cert *x509.Certificate) string { return cert.SerialNumber.Text(16) }

func runACMERollover(ctx context.Context, out io.Writer, conn connection, account acmeAccount) error {
	oldKey, err := readAccountKey(account.accountKey)
	if err != nil {
		return err
	}
	// The new key is saved before the CA hears of it: once the CA has
	// switched, a key that exists only in memory would be the account's
	// only way in.
	newPath := account.accountKey + ".new"
	if _, err := os.Stat(newPath); err == nil {
		return fmt.Errorf("%s exists, from an earlier rollover. If that one finished, it is the account's key now:\n"+
			"try it with --account-key %s. Otherwise delete it and run this again", newPath, newPath)
	}
	newKey, err := newKeyLike(oldKey)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(newKey)
	if err != nil {
		return err
	}
	if err := writePrivateFile(newPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return err
	}

	acmeClient, err := newACMEClient(conn, account.directory, oldKey)
	if err != nil {
		os.Remove(newPath)
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, acmeTimeout)
	defer cancel()
	if err := acmeClient.AccountKeyRollover(ctx, newKey); err != nil {
		os.Remove(newPath)
		if errors.Is(err, acme.ErrNoAccount) {
			return fmt.Errorf("the CA has no account with the key in %s", account.accountKey)
		}
		return fmt.Errorf("the CA did not accept the new key; the old one stays: %w", err)
	}
	if err := os.Rename(newPath, account.accountKey); err != nil {
		return fmt.Errorf("the CA switched to the new key, but it could not be put in place: %w\n"+
			"The account's key is now %s: move it to %s yourself", err, newPath, account.accountKey)
	}
	fmt.Fprintf(out, "New account key: %s\n", account.accountKey)
	return nil
}

func runACMEDeactivate(ctx context.Context, out io.Writer, conn connection, account acmeAccount, confirm func(string) (bool, error)) error {
	key, err := readAccountKey(account.accountKey)
	if err != nil {
		return err
	}
	acmeClient, err := newACMEClient(conn, account.directory, key)
	if err != nil {
		return err
	}
	if confirm != nil {
		ok, err := confirm(fmt.Sprintf("Close the ACME account of %s at %s for good?", account.accountKey, acmeClient.DirectoryURL))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("nothing changed")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, acmeTimeout)
	defer cancel()
	if err := acmeClient.DeactivateReg(ctx); err != nil {
		if errors.Is(err, acme.ErrNoAccount) {
			return fmt.Errorf("the CA has no account with the key in %s", account.accountKey)
		}
		return fmt.Errorf("the CA did not close the account: %w", err)
	}
	fmt.Fprintf(out, "Closed:       the ACME account of %s; the key is of no further use\n", account.accountKey)
	return nil
}

func findChallenge(authz *acme.Authorization, kind string) *acme.Challenge {
	for _, challenge := range authz.Challenges {
		if challenge.Type == kind {
			return challenge
		}
	}
	return nil
}

// challengeAnswerer answers the CA's challenge requests for one kind of
// challenge.
type challengeAnswerer interface {
	// prepare puts the answer to a challenge in place.
	prepare(client *acme.Client, challenge *acme.Challenge, name string) error
	stop()
}

func (r *challengeResponder) prepare(client *acme.Client, challenge *acme.Challenge, _ string) error {
	answer, err := client.HTTP01ChallengeResponse(challenge.Token)
	if err != nil {
		return err
	}
	r.answer(client.HTTP01ChallengePath(challenge.Token), answer)
	return nil
}

// alpnResponder answers tls-alpn-01: a TLS server that shows, for each
// name, the certificate the CA looks for (RFC 8737).
type alpnResponder struct {
	listener net.Listener
	mu       sync.Mutex
	certs    map[string]*tls.Certificate // name -> challenge certificate
}

func startALPNResponder(address string) (*alpnResponder, error) {
	r := &alpnResponder{certs: make(map[string]*tls.Certificate)}
	config := &tls.Config{
		NextProtos: []string{"acme-tls/1"},
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			if cert, ok := r.certs[strings.ToLower(hello.ServerName)]; ok {
				return cert, nil
			}
			return nil, fmt.Errorf("no challenge for %q", hello.ServerName)
		},
	}
	listener, err := tls.Listen("tcp", address, config)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on %s for the CA's challenge: %w\n"+
			"Port 443 usually needs root, and no other server may be using it", address, err)
	}
	r.listener = listener
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				// The CA only needs the handshake.
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	return r, nil
}

func (r *alpnResponder) prepare(client *acme.Client, challenge *acme.Challenge, name string) error {
	var cert tls.Certificate
	var err error
	serverName := strings.ToLower(name)
	if ip := net.ParseIP(name); ip != nil {
		// For an IP address the CA asks for the reverse name, and the
		// certificate carries the address (RFC 8738).
		serverName = caacme.ReverseName(ip)
		cert, err = ipChallengeCert(client, challenge.Token, ip)
	} else {
		cert, err = client.TLSALPN01ChallengeCert(challenge.Token, name)
	}
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.certs[serverName] = &cert
	return nil
}

// ipChallengeCert makes the tls-alpn-01 certificate for an IP address.
func ipChallengeCert(client *acme.Client, token string, ip net.IP) (tls.Certificate, error) {
	keyAuth, err := client.HTTP01ChallengeResponse(token)
	if err != nil {
		return tls.Certificate{}, err
	}
	ext, err := caacme.ACMEIdentifierExtension(keyAuth)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "ACME challenge"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		IPAddresses:     []net.IP{ip},
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func (r *alpnResponder) stop() { r.listener.Close() }

// challengeResponder is the small web server that answers the CA's
// challenge requests.
type challengeResponder struct {
	server *http.Server

	mu      sync.Mutex
	answers map[string]string // path -> text to answer with
}

func startChallengeResponder(address string) (*challengeResponder, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on %s for the CA's challenge request: %w\n"+
			"Port 80 usually needs root, and no other web server may be using it", address, err)
	}
	r := &challengeResponder{answers: make(map[string]string)}
	r.server = &http.Server{Handler: r, ReadHeaderTimeout: 10 * time.Second}
	go r.server.Serve(listener)
	return r, nil
}

// answer makes the responder reply with text at path.
func (r *challengeResponder) answer(path, text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers[path] = text
}

func (r *challengeResponder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	text, ok := r.answers[req.URL.Path]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	io.WriteString(w, text)
}

func (r *challengeResponder) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = r.server.Shutdown(ctx)
}

// loadOrCreateAccountKey reads the ACME account key, or makes a P-256 key
// and saves it there if the file does not exist.
func loadOrCreateAccountKey(path string) (crypto.Signer, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		if err := writePrivateFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
			return nil, err
		}
		return key, nil
	}
	return readAccountKey(path)
}

// readAccountKey reads an existing ACME account key: ECDSA or RSA, in
// any of the PEM forms ACME clients write (lego and certbot keys work).
func readAccountKey(path string) (crypto.Signer, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no ACME account key at %s: give it with --account-key", path)
	}
	key, err := readPrivateKey(path)
	if err != nil {
		return nil, err
	}
	switch key.(type) {
	case *ecdsa.PrivateKey, *rsa.PrivateKey:
		return key, nil
	}
	return nil, fmt.Errorf("%s: ACME account keys must be ECDSA or RSA", path)
}

// writePrivateFile writes a file that only the owner can read.
func writePrivateFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	// WriteFile keeps the mode of a file that already exists.
	return os.Chmod(path, 0o600)
}
