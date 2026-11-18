// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/ca"
)

// tlsOptions are the settings of "bxp tls".
type tlsOptions struct {
	names    []string      // DNS names, IP addresses, email addresses
	template string        // only used without a token: tls-server or tls-client
	outDir   string        // where the key and certificate files go
	validity time.Duration // zero: the server's default
	force    bool          // replace existing files
}

func newTLSCommand() *cobra.Command {
	conn := connection{openBrowser: openBrowser}
	var opts tlsOptions

	cmd := &cobra.Command{
		Use:   "tls",
		Short: "Create a key and get a TLS certificate for it",
		Long: "Create a new private key, ask the CA for a TLS certificate and write\n" +
			"both to files named after the first name. Run this on the machine that\n" +
			"needs the certificate; it needs no configuration file.\n\n" +
			"  <name>.key   the private key (it never leaves this machine)\n" +
			"  <name>.crt   the certificate, followed by the intermediate certificate\n\n" +
			"With --token, the token decides whether this is a server or a client\n" +
			"certificate and which names are allowed. Without one, your browser\n" +
			"opens for a login with your identity provider (or, with --ldap, you\n" +
			"give your directory password); you must be an admin\n" +
			"of the CA, and --profile chooses the kind.",
		Example: "  bxp tls --ca-url https://ca.example.com:8443 --root root.crt \\\n" +
			"      --token $TOKEN --name web.example.com --name 10.0.0.5",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTLS(cmd.Context(), cmd.OutOrStdout(), conn, opts)
		},
	}
	addConnectionFlags(cmd, &conn, true)
	cmd.Flags().StringArrayVar(&opts.names, "name", nil,
		"a name for the certificate: DNS name, IP address or email address (repeat for more).\n"+
			"Default with --token: all the names the token allows")
	cmd.Flags().StringVar(&opts.template, "profile", "",
		"tls-server, tls-client or one of the CA's profiles. Only used without --token: a token already says which.\n"+
			"Default: tls-server with --name; without --name, the client certificate the CA gives you for yourself")
	cmd.Flags().StringVar(&opts.outDir, "out-dir", ".", "directory to write the key and certificate to")
	cmd.Flags().DurationVar(&opts.validity, "validity", 0,
		"how long the certificate should be valid, e.g. 24h (default: decided by the CA)")
	cmd.Flags().BoolVar(&opts.force, "force", false, "replace the key and certificate files if they exist")
	return cmd
}

func runTLS(ctx context.Context, out io.Writer, conn connection, opts tlsOptions) error {
	// A token without --name: the names it was made for.
	if len(opts.names) == 0 && conn.token != "" {
		names, err := namesFromToken(conn.token)
		if err != nil {
			return err
		}
		opts.names = names
	}
	// Without names and without a token: a client certificate for
	// yourself, after a login. The CA decides the name: yours.
	forYourself := len(opts.names) == 0

	if opts.template == "" && !forYourself {
		opts.template = "tls-server"
	}
	if !forYourself {
		// Check the files before talking to the CA: a token works only
		// once, so do not spend it and then fail to save the result.
		if err := checkTLSFiles(opts.outDir, opts.names[0], opts.force); err != nil {
			return err
		}
	}
	caClient, err := conn.newClient()
	if err != nil {
		return err
	}

	// The key is made here and stays here. The CA only sees the CSR,
	// which contains the public key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// If this needs a login, tell the CA which key the token is for.
	// The token then works for this key only.
	fingerprint, err := ca.X509Fingerprint(key.Public())
	if err != nil {
		return err
	}
	oneTime, err := conn.oneTimeToken(ctx, caClient, loginRequest{
		template:       opts.template,
		kind:           "x509",
		names:          opts.names,
		keyFingerprint: fingerprint,
	})
	if err != nil {
		return err
	}

	var csrPEM []byte
	if forYourself {
		// The name is the one the CA put into the token: yours.
		names, err := tokenNames(oneTime)
		if err != nil {
			return err
		}
		opts.names = names
		if err := checkTLSFiles(opts.outDir, names[0], opts.force); err != nil {
			return err
		}
		csrPEM, err = newPersonCSR(key, names[0])
		if err != nil {
			return err
		}
	} else if csrPEM, err = newCSR(key, opts.names); err != nil {
		return err
	}
	keyFile := filepath.Join(opts.outDir, opts.names[0]+".key")
	certFile := filepath.Join(opts.outDir, opts.names[0]+".crt")

	req := api.SignX509Request{CSR: string(csrPEM)}
	if opts.validity != 0 {
		req.Validity = opts.validity.String()
	}
	resp, err := caClient.SignX509(ctx, oneTime, req)
	if err != nil {
		return err
	}

	if err := writePrivateFile(keyFile, keyPEM); err != nil {
		return err
	}
	if err := os.WriteFile(certFile, []byte(resp.Chain), 0o644); err != nil {
		return err
	}

	fmt.Fprintf(out, "Private key:  %s\n", keyFile)
	fmt.Fprintf(out, "Certificate:  %s\n", certFile)
	if notAfter, err := certNotAfter(resp.Certificate); err == nil {
		fmt.Fprintf(out, "Valid until:  %s\n", notAfter.Local().Format("2006-01-02 15:04 MST"))
	}
	return nil
}

// checkTLSFiles makes sure the key and certificate files for name may be
// written.
func checkTLSFiles(outDir, name string, force bool) error {
	if force {
		return nil
	}
	for _, file := range []string{filepath.Join(outDir, name+".key"), filepath.Join(outDir, name+".crt")} {
		if _, err := os.Stat(file); err == nil {
			return fmt.Errorf("%s already exists: use --force to replace it", file)
		}
	}
	return nil
}

// newPersonCSR builds the CSR of a person's own client certificate: their
// name as the common name, and as an email address if it is one. A name
// such as "alice" is not a host name, so it goes into no DNS name.
func newPersonCSR(key *ecdsa.PrivateKey, name string) ([]byte, error) {
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}
	if strings.Contains(name, "@") {
		template.EmailAddresses = []string{name}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// tokenNames reads the names a one-time token allows. The token came from
// the CA over a connection checked against its root, so it is read, not
// verified: the CA verifies it when it is used.
func tokenNames(oneTime string) ([]string, error) {
	parts := strings.Split(oneTime, ".")
	if len(parts) != 3 {
		return nil, errors.New("the CA sent something that is not a token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("the CA sent something that is not a token")
	}
	var claims struct {
		Names []string `json:"names"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || len(claims.Names) == 0 {
		return nil, errors.New("the CA's token names no certificate name")
	}
	return claims.Names, nil
}

// namesFromToken reads the names of a token given with --token, for when
// --name is left out. The CA checks the token when it is used.
func namesFromToken(oneTime string) ([]string, error) {
	names, err := tokenNames(oneTime)
	if err != nil {
		return nil, errors.New("the token cannot be read: give the names with --name")
	}
	return names, nil
}

// newCSR builds a certificate signing request for the names. The first
// name becomes the common name. Each name also goes into the list that
// TLS clients really check (the subject alternative names), in the place
// that fits its kind.
func newCSR(key *ecdsa.PrivateKey, names []string) ([]byte, error) {
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}}
	for _, name := range names {
		switch ip := net.ParseIP(name); {
		case name == "":
			return nil, errors.New("empty name")
		case ip != nil:
			template.IPAddresses = append(template.IPAddresses, ip)
		case strings.Contains(name, "@"):
			template.EmailAddresses = append(template.EmailAddresses, name)
		default:
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// certNotAfter returns the expiry time of a PEM certificate.
func certNotAfter(certPEM string) (time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return time.Time{}, errors.New("no PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}
