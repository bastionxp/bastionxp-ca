// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/client"
	"github.com/bastionxp/bastionxp-ca/internal/scep"
)

// scepOptions are the settings of "bxp scep".
type scepOptions struct {
	names    []string // DNS names, IP addresses, email addresses
	template string   // only used without a token: tls-client or tls-server
	outDir   string   // where the key and certificate files go
	force    bool     // replace existing files
}

func newSCEPCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scep",
		Short: "Get, renew or fetch a TLS certificate over SCEP",
		Long: "The SCEP protocol, the one that phones, managed laptops, routers and\n" +
			"printers use. On a normal machine, \"bxp tls\" and \"bxp renew\"\n" +
			"are simpler; these commands are here to try out the CA's SCEP server,\n" +
			"and for scripts that stand in for a device.\n\n" +
			"  enroll   get a certificate, with a one-time token as the challenge\n" +
			"  renew    get a new one, signed with the current certificate: no token\n" +
			"  getcert  fetch a certificate the CA issued before, with its key\n\n" +
			"SCEP needs RSA keys.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newSCEPEnrollCommand(), newSCEPRenewCommand(), newSCEPGetCertCommand())
	return cmd
}

func newSCEPEnrollCommand() *cobra.Command {
	conn := connection{openBrowser: openBrowser}
	var opts scepOptions

	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Get a TLS certificate over SCEP",
		Long: "Get a TLS certificate with SCEP. The result is the same as with\n" +
			"\"bxp tls\".\n\n" +
			"The one-time token travels as the SCEP \"challenge password\". The key\n" +
			"is an RSA key, because SCEP cannot work with other kinds. It writes:\n\n" +
			"  <name>.key   the private key (it never leaves this machine)\n" +
			"  <name>.crt   the certificate, followed by the intermediate certificate",
		Example: "  bxp scep enroll --ca-url https://ca.example.com:8443 --root root.crt \\\n" +
			"      --token $TOKEN --name device1.example.com",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSCEP(cmd.Context(), cmd.OutOrStdout(), conn, opts)
		},
	}
	addConnectionFlags(cmd, &conn, true)
	cmd.Flags().StringArrayVar(&opts.names, "name", nil,
		"a name for the certificate: DNS name, IP address or email address (repeat for more).\n"+
			"Default with --token: all the names the token allows")
	cmd.Flags().StringVar(&opts.template, "profile", "tls-device",
		"tls-device, tls-client, tls-server or one of the CA's profiles. Only used without --token: a token already says which")
	cmd.Flags().StringVar(&opts.outDir, "out-dir", ".", "directory to write the key and certificate to")
	cmd.Flags().BoolVar(&opts.force, "force", false, "replace the key and certificate files if they exist")
	return cmd
}

func newSCEPRenewCommand() *cobra.Command {
	var conn connection
	var opts renewOptions
	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew a certificate over SCEP: no token",
		Long: "Renew a certificate with SCEP's renewal request: the request is\n" +
			"signed with the current certificate and its key, so no token is needed.\n" +
			"The new certificate has the same names and profile as the old one.\n\n" +
			"It does nothing while more than a third of the certificate's lifetime\n" +
			"is left, so run it from a timer: daily for tls-device's 30 days, hourly\n" +
			"for certificates of a day or two. A new RSA key of the same size\n" +
			"is made, and the key and certificate files are replaced.\n\n" +
			"A certificate that has expired or was revoked cannot be renewed.",
		Example: "  bxp scep renew --cert device1.example.com.crt --key device1.example.com.key",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSCEPRenew(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), conn, opts)
		},
	}
	addConnectionFlags(cmd, &conn, false)
	cmd.Flags().StringVar(&opts.cert, "cert", "", "the certificate to renew")
	cmd.Flags().StringVar(&opts.key, "key", "", "its private key (RSA)")
	cmd.Flags().BoolVar(&opts.force, "force", false, "renew now, even if more than a third of the lifetime is left")
	cmd.Flags().StringVar(&opts.exec, "exec", "", "a command to run after a renewal")
	return cmd
}

// scepGetCertOptions are the settings of "bxp scep getcert".
type scepGetCertOptions struct {
	serial string // hex
	key    string // the certificate's private key
	out    string // where to write the certificate
	force  bool
}

func newSCEPGetCertCommand() *cobra.Command {
	var conn connection
	var opts scepGetCertOptions
	cmd := &cobra.Command{
		Use:   "getcert",
		Short: "Fetch a certificate the CA issued before",
		Long: "Fetch a certificate the CA issued, by its serial number: for a device\n" +
			"that lost its certificate file but kept its key. The CA hands a\n" +
			"certificate only to the holder of its key, so give the key with --key.",
		Example: "  bxp scep getcert --serial 2674c91e0dadae73aaba34dd46d5128c53a49287 \\\n" +
			"      --key device1.example.com.key --out device1.example.com.crt",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSCEPGetCert(cmd.Context(), cmd.OutOrStdout(), conn, opts)
		},
	}
	addConnectionFlags(cmd, &conn, false)
	cmd.Flags().StringVar(&opts.serial, "serial", "", "the certificate's serial number, in hex (as \"bxp list certificates\" shows it)")
	cmd.Flags().StringVar(&opts.key, "key", "", "the certificate's private key (RSA)")
	cmd.Flags().StringVar(&opts.out, "out", "", "file to write the certificate to (default: <serial>.crt)")
	cmd.Flags().BoolVar(&opts.force, "force", false, "replace the file if it exists")
	return cmd
}

// scepSession connects to the CA's SCEP server and learns its
// certificates, checked against the CA's root if it is known.
func scepSession(ctx context.Context, conn connection) (*scep.Client, *scep.CACerts, error) {
	if conn.url == "" {
		return nil, nil, fmt.Errorf("give the CA server's address with --ca-url or %s", envURL)
	}
	httpClient, err := client.NewHTTPClient(conn.root)
	if err != nil {
		return nil, nil, err
	}
	scepClient := scep.NewClient(strings.TrimRight(conn.url, "/")+scep.Path, httpClient)
	caCerts, err := scepClient.GetCACerts(ctx)
	if err != nil {
		return nil, nil, err
	}
	if conn.root != "" {
		rootPEM, err := os.ReadFile(conn.root)
		if err != nil {
			return nil, nil, err
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(rootPEM)
		if err := caCerts.VerifyRA(roots); err != nil {
			return nil, nil, err
		}
	}
	return scepClient, caCerts, nil
}

// scepChain returns cert as PEM, followed by the CA certificate that
// signed it, like the other client commands write it.
func scepChain(cert *x509.Certificate, caCerts *scep.CACerts) []byte {
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	for _, caCert := range caCerts.Others {
		if bytes.Equal(caCert.RawSubject, cert.RawIssuer) {
			chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...)
		}
	}
	return chain
}

func runSCEPRenew(ctx context.Context, out, errOut io.Writer, conn connection, opts renewOptions) error {
	if opts.cert == "" || opts.key == "" {
		return errors.New("give the certificate with --cert and its private key with --key")
	}
	old, err := readLeaf(opts.cert)
	if err != nil {
		return err
	}
	if goOn, err := checkTiming(out, old.NotBefore, old.NotAfter, opts.force); !goOn || err != nil {
		return err
	}
	signer, err := readPrivateKey(opts.key)
	if err != nil {
		return err
	}
	oldKey, ok := signer.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("%s is not an RSA key: SCEP needs RSA", opts.key)
	}
	if !sameKey(oldKey.Public(), old.PublicKey) {
		return fmt.Errorf("%s is not the key of %s", opts.key, opts.cert)
	}
	if err := checkReplaceable(opts.key, opts.cert); err != nil {
		return err
	}
	scepClient, caCerts, err := scepSession(ctx, conn)
	if err != nil {
		return err
	}
	caps, err := scepClient.Capabilities(ctx)
	if err != nil {
		return err
	}
	if !slices.Contains(caps, "Renewal") {
		return errors.New("the SCEP server does not offer renewal")
	}

	newKey, err := rsa.GenerateKey(rand.Reader, oldKey.N.BitLen())
	if err != nil {
		return err
	}
	// A plain CSR: the CA takes the names from the current certificate.
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: old.Subject}, newKey)
	if err != nil {
		return err
	}
	cert, err := scepClient.Renew(ctx, csr, old, oldKey, caCerts)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(newKey)
	if err != nil {
		return err
	}
	if err := replaceFile(opts.key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := replaceFile(opts.cert, scepChain(cert, caCerts), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "Renewed:      %s\n", opts.cert)
	fmt.Fprintf(out, "Valid until:  %s\n", cert.NotAfter.Local().Format("2006-01-02 15:04 MST"))
	if opts.exec == "" {
		return nil
	}
	fmt.Fprintf(out, "Running:      %s\n", opts.exec)
	if err := runShell(ctx, opts.exec, out, errOut); err != nil {
		return fmt.Errorf("the certificate was renewed, but %q failed: %w", opts.exec, err)
	}
	return nil
}

func runSCEPGetCert(ctx context.Context, out io.Writer, conn connection, opts scepGetCertOptions) error {
	if opts.serial == "" || opts.key == "" {
		return errors.New("give the serial number with --serial and the certificate's key with --key")
	}
	serial, ok := new(big.Int).SetString(strings.TrimPrefix(strings.ReplaceAll(strings.ToLower(opts.serial), ":", ""), "0x"), 16)
	if !ok {
		return fmt.Errorf("--serial %q is not a hex number", opts.serial)
	}
	if opts.out == "" {
		opts.out = serial.Text(16) + ".crt"
	}
	if !opts.force {
		if _, err := os.Stat(opts.out); err == nil {
			return fmt.Errorf("%s already exists: use --force to replace it", opts.out)
		}
	}
	signer, err := readPrivateKey(opts.key)
	if err != nil {
		return err
	}
	key, ok := signer.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("%s is not an RSA key: SCEP needs RSA", opts.key)
	}
	scepClient, caCerts, err := scepSession(ctx, conn)
	if err != nil {
		return err
	}
	// The issuer: the CA's issuing certificate, which the server lists
	// first.
	if len(caCerts.Others) == 0 {
		return errors.New("the SCEP server sent no CA certificate")
	}
	cert, err := scepClient.GetCert(ctx, caCerts.Others[0], serial, key, caCerts)
	if err != nil {
		return err
	}
	if err := os.WriteFile(opts.out, scepChain(cert, caCerts), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "Certificate:  %s (%s)\n", opts.out, cert.Subject.CommonName)
	fmt.Fprintf(out, "Valid until:  %s\n", cert.NotAfter.Local().Format("2006-01-02 15:04 MST"))
	return nil
}

func runSCEP(ctx context.Context, out io.Writer, conn connection, opts scepOptions) error {
	// A token without --name: the names it was made for.
	if len(opts.names) == 0 && conn.token != "" {
		names, err := namesFromToken(conn.token)
		if err != nil {
			return err
		}
		opts.names = names
	}
	if len(opts.names) == 0 {
		return errors.New("give at least one name with --name")
	}
	keyFile := filepath.Join(opts.outDir, opts.names[0]+".key")
	certFile := filepath.Join(opts.outDir, opts.names[0]+".crt")
	// Check the files before talking to the CA: a token works only once.
	if !opts.force {
		for _, file := range []string{keyFile, certFile} {
			if _, err := os.Stat(file); err == nil {
				return fmt.Errorf("%s already exists: use --force to replace it", file)
			}
		}
	}
	caClient, err := conn.newClient()
	if err != nil {
		return err
	}
	// 1. The server's certificates, checked against the CA's root.
	scepClient, caCerts, err := scepSession(ctx, conn)
	if err != nil {
		return err
	}

	// 2. The key, made here. SCEP needs RSA.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	fingerprint, err := ca.X509Fingerprint(key.Public())
	if err != nil {
		return err
	}
	oneTime, err := conn.oneTimeToken(ctx, caClient, loginRequest{
		template:       opts.template,
		names:          opts.names,
		keyFingerprint: fingerprint,
	})
	if err != nil {
		return err
	}

	// 3. The CSR, with the token as its challenge, and the request.
	csr, err := scep.NewCSR(scepCSRTemplate(opts.names), key, oneTime)
	if err != nil {
		return err
	}
	cert, err := scepClient.Enroll(ctx, csr, key, caCerts)
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
	if err := os.WriteFile(certFile, scepChain(cert, caCerts), 0o644); err != nil {
		return err
	}

	fmt.Fprintf(out, "Private key:  %s\n", keyFile)
	fmt.Fprintf(out, "Certificate:  %s\n", certFile)
	fmt.Fprintf(out, "Valid until:  %s\n", cert.NotAfter.Local().Format("2006-01-02 15:04 MST"))
	return nil
}

// scepCSRTemplate describes the CSR for the names. The first name becomes
// the common name; each name also goes where its kind belongs.
func scepCSRTemplate(names []string) *x509.CertificateRequest {
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}}
	for _, name := range names {
		switch ip := net.ParseIP(name); {
		case ip != nil:
			template.IPAddresses = append(template.IPAddresses, ip)
		case strings.Contains(name, "@"):
			template.EmailAddresses = append(template.EmailAddresses, name)
		default:
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	return template
}
