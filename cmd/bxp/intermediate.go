// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
	"github.com/bastionxp/bastionxp-ca/internal/keyfile"
	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// replaceOptions are the settings of "bxp new-intermediate".
type replaceOptions struct {
	rootKey        string
	rootPassphrase []byte
	// yes replaces the intermediate even if certificates it issued are
	// still valid, without asking.
	yes bool
	// confirm asks the person; nil means there is nobody to ask.
	confirm func(question string) (bool, error)

	// Under another root (see "bxp init --external-root"):
	csr        bool     // make a key and a CSR for the root's CA to sign
	importCert string   // the signed certificate to put in place
	issuingCAs []string // the CAs between it and the root, if any
	rootCA     string   // the root certificate, the first time
}

func newIntermediateCommand(configPath *string) *cobra.Command {
	var opts replaceOptions
	var rootPassphraseFile string
	cmd := &cobra.Command{
		Use:   "new-intermediate",
		Short: "Replace the intermediate certificate, with the offline root key",
		Long: "Make a new intermediate certificate, signed by the root key, in place\n" +
			"of the current one. BastionXP CA has exactly one intermediate: from the next\n" +
			"start of \"bxp serve\", the new one signs everything.\n\n" +
			"Do it before the current one expires (the server warns a year ahead),\n" +
			"or if its key may be in the wrong hands. Run it on the CA machine, with\n" +
			"the root key from wherever you keep it offline, and its passphrase.\n\n" +
			"The old intermediate key is removed. Certificates it issued stay valid,\n" +
			"because they chain to the same root, but revoking them no longer works:\n" +
			"the CRL and OCSP answers come from the new intermediate. Renew them to\n" +
			"move them over. The command says how many there are and asks first.",
		Example: "  # with BastionXP CA's own root\n" +
			"  bxp new-intermediate --config bastionxp-ca.yaml --root-key /media/usb/root.key\n\n" +
			"  # under another root (bxp init --external-root): a CSR, then its certificate\n" +
			"  bxp new-intermediate --config bastionxp-ca.yaml --csr\n" +
			"  bxp new-intermediate --config bastionxp-ca.yaml --import bastionxp-ca.crt \\\n" +
			"      --root-ca corp-root.crt --issuing-ca corp-issuing-ca.crt",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			prompt := cmd.ErrOrStderr()
			opts.confirm = terminalConfirm(prompt)
			switch {
			case opts.csr && opts.importCert != "":
				return errors.New("give --csr or --import, not both")
			case opts.csr:
				return runIntermediateCSR(cmd.OutOrStdout(), prompt, cfg)
			case opts.importCert != "":
				return runImportIntermediate(cmd.Context(), cmd.OutOrStdout(), prompt, cfg, opts)
			}
			if opts.rootKey == "" {
				opts.rootKey = filepath.Join(cfg.DataDir, ca.RootKeyFile)
				if _, err := os.Stat(opts.rootKey); err != nil {
					return errors.New("give the root key's file with --root-key")
				}
			}
			if rootPassphraseFile != "" {
				opts.rootPassphrase, err = readPassphraseFile(rootPassphraseFile)
			} else {
				var asked string
				asked, err = askSecret(prompt, "Passphrase of the root key")
				opts.rootPassphrase = []byte(asked)
			}
			if err != nil {
				return fmt.Errorf("root key passphrase: %w", err)
			}
			return runNewIntermediate(cmd.Context(), cmd.OutOrStdout(), prompt, cfg, opts)
		},
	}
	cmd.Flags().StringVar(&opts.rootKey, "root-key", "", "the root key's file (default: data_dir/root.key, if it is there)")
	cmd.Flags().StringVar(&rootPassphraseFile, "root-passphrase-file", "",
		"read the root key's passphrase from this file instead of asking (/dev/stdin works)")
	cmd.Flags().BoolVar(&opts.yes, "yes", false,
		"replace it without asking, even if certificates it issued are still valid")
	cmd.Flags().BoolVar(&opts.csr, "csr", false,
		"under another root: make the new key and a CSR for that root's CA to sign")
	cmd.Flags().StringVar(&opts.importCert, "import", "",
		"under another root: put the certificate the CA issued for the CSR in place")
	cmd.Flags().StringArrayVar(&opts.issuingCAs, "issuing-ca", nil,
		"with --import: the CA that signed the certificate, if it is not the root (PEM).\n"+
			"Repeat for each level up to the root, or give one file with all of them")
	cmd.Flags().StringVar(&opts.rootCA, "root-ca", "",
		"with --import, the first time: the root CA certificate (PEM)")
	return cmd
}

func runNewIntermediate(ctx context.Context, out, prompt io.Writer, cfg *config.Config, opts replaceOptions) error {
	// Open the server's keys first: the new key gets their passphrase,
	// and this checks it before anything changes.
	keys, err := loadServerKeys(cfg, prompt)
	if err != nil {
		return err
	}
	rootKey, err := keyfile.Read(opts.rootKey, opts.rootPassphrase)
	if errors.Is(err, keyfile.ErrWrongPassphrase) {
		return errors.New("wrong passphrase for the root key")
	}
	if err != nil {
		return err
	}
	old := keys.ca.IntermediateCert()

	valid, err := stillValid(ctx, cfg, old)
	if err != nil {
		return err
	}
	if valid > 0 && !opts.yes {
		warning := fmt.Sprintf("%d certificate(s) from the current intermediate are still valid. After the change,\n"+
			"revoking them no longer works until they are renewed.", valid)
		if opts.confirm == nil {
			return errors.New(warning + "\nGive --yes to replace the intermediate all the same")
		}
		fmt.Fprintln(prompt, warning)
		ok, err := opts.confirm("Replace the intermediate?")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("nothing changed")
		}
	}

	cert, err := ca.ReplaceIntermediate(cfg.DataDir, ca.ReplaceOptions{
		Name:          cfg.CA.Name,
		Organization:  cfg.CA.Organization,
		KeyType:       cfg.CA.KeyType,
		RootKey:       rootKey,
		KeyPassphrase: keys.passphrase,
		// From the configuration as it is now: this is how constraints
		// change.
		NameConstraints: cfg.CA.NameConstraints.CA(),
		Validity:        cfg.CA.IntermediateLifetime(),
	})
	if err != nil {
		return err
	}

	fmt.Fprintln(out, "The intermediate certificate was replaced.")
	fmt.Fprintf(out, "\n  New:  valid until %s\n", cert.NotAfter.Format("2006-01-02"))
	fmt.Fprintf(out, "  Old:  key removed, certificate kept in %s\n", filepath.Join(cfg.DataDir, ca.ReplacedDir))
	fmt.Fprintln(out, "\nRestart \"bxp serve\" to sign with the new one. Put the root key back offline.")
	return nil
}

// stillValid counts the TLS certificates the intermediate issued that are
// neither expired nor revoked. The server's own certificate does not
// count: the server makes a new one when it starts.
func stillValid(ctx context.Context, cfg *config.Config, intermediate *x509.Certificate) (int, error) {
	db, err := store.Open(filepath.Join(cfg.DataDir, store.FileName))
	if err != nil {
		return 0, err
	}
	defer db.Close()
	certs, err := db.Certificates(ctx, false)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	n := 0
	for _, c := range certs {
		if c.Kind != store.KindX509 || c.Template == ca.OwnServerCert || c.Revoked() || now.After(c.NotAfter) {
			continue
		}
		block, _ := pem.Decode([]byte(c.Body))
		if block == nil {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil && ca.IssuedBy(cert, intermediate) {
			n++
		}
	}
	return n, nil
}

// runIntermediateCSR makes the next intermediate key and its CSR, for a CA
// under another root.
func runIntermediateCSR(out, prompt io.Writer, cfg *config.Config) error {
	if err := refuseExternalValidity(cfg); err != nil {
		return err
	}
	keys, err := loadServerKeys(cfg, prompt)
	if err != nil {
		return err
	}
	if _, err := ca.NewIntermediateCSR(cfg.DataDir, ca.IntermediateCSROptions{
		Name: cfg.CA.Name, Organization: cfg.CA.Organization, KeyType: cfg.CA.KeyType, KeyPassphrase: keys.passphrase,
	}); err != nil {
		return err
	}
	printCSRSteps(out, cfg, true)
	return nil
}

func printCSRSteps(out io.Writer, cfg *config.Config, withPath bool) {
	if withPath {
		csr := filepath.Join(cfg.DataDir, ca.NextIntermediateCSRFile)
		fmt.Fprintf(out, "CSR for the intermediate:  %s\n\n", csr)
	}
	fmt.Fprintln(out, "Have the root's CA sign it as a subordinate CA. With Active Directory")
	fmt.Fprintln(out, "Certificate Services, on a machine that can reach the CA:")
	fmt.Fprintf(out, "  certreq -submit -attrib \"CertificateTemplate:SubCA\" %s bastionxp-ca.crt\n\n", ca.NextIntermediateCSRFile)
	fmt.Fprintln(out, "Then put the certificate in place, with the CAs between it and the root if any:")
	fmt.Fprintln(out, "  bxp new-intermediate --import bastionxp-ca.crt --root-ca corp-root.crt [--issuing-ca corp-issuing-ca.crt]")
	fmt.Fprintln(out, "(--root-ca only the first time; --issuing-ca if the root's CA did not sign it itself.)")
}

// runImportIntermediate puts the certificate for the waiting CSR in
// place: the first one of a CA under another root, or a replacement.
func runImportIntermediate(ctx context.Context, out, prompt io.Writer, cfg *config.Config, opts replaceOptions) error {
	if err := refuseExternalValidity(cfg); err != nil {
		return err
	}
	readOne := func(path string) (*x509.Certificate, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		certs, err := ca.ParseCerts(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return certs[0], nil
	}
	cert, err := readOne(opts.importCert)
	if err != nil {
		return err
	}
	var chain []*x509.Certificate
	for _, file := range opts.issuingCAs {
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		certs, err := ca.ParseCerts(data)
		if err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		chain = append(chain, certs...)
	}
	var root *x509.Certificate
	if opts.rootCA != "" {
		if root, err = readOne(opts.rootCA); err != nil {
			return err
		}
	}

	// The passphrase of the waiting key: the server's.
	passphrase, _, err := keyPassphrase(cfg)
	if err != nil {
		return err
	}
	nextKey := filepath.Join(cfg.DataDir, ca.NextIntermediateKeyFile)
	if encrypted, _ := keyfile.IsEncrypted(nextKey); encrypted && passphrase == nil {
		asked, err := askSecret(prompt, "Passphrase of the CA keys")
		if err != nil {
			return errors.New("the keys are encrypted: give their passphrase as for bxp serve")
		}
		passphrase = []byte(asked)
	}

	// A replacement: the same warning as with BastionXP CA's own root.
	if current, err := ca.Load(cfg.DataDir, passphrase); err == nil {
		valid, err := stillValid(ctx, cfg, current.IntermediateCert())
		if err != nil {
			return err
		}
		if valid > 0 && !opts.yes {
			warning := fmt.Sprintf("%d certificate(s) from the current intermediate are still valid. After the change,\n"+
				"revoking them no longer works until they are renewed.", valid)
			if opts.confirm == nil {
				return errors.New(warning + "\nGive --yes to replace the intermediate all the same")
			}
			fmt.Fprintln(prompt, warning)
			if ok, err := opts.confirm("Replace the intermediate?"); err != nil || !ok {
				return errors.New("nothing changed")
			}
		}
	}

	if err := ca.ImportIntermediate(cfg.DataDir, ca.ImportOptions{
		Cert: cert, Chain: chain, Root: root, KeyPassphrase: passphrase,
	}); err != nil {
		return err
	}
	fmt.Fprintln(out, "The intermediate certificate is in place.")
	fmt.Fprintf(out, "\n  Issued by:    %s\n", cert.Issuer.CommonName)
	fmt.Fprintf(out, "  Valid until:  %s\n", cert.NotAfter.Format("2006-01-02"))
	fmt.Fprintln(out, "\n(Re)start \"bxp serve\" to sign with it.")
	return nil
}
