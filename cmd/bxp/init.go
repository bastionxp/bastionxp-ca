// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
	"github.com/bastionxp/bastionxp-ca/internal/token"
)

// initOptions are the secrets and places "bxp init" works with.
type initOptions struct {
	// rootPassphrase encrypts the root key. Required.
	rootPassphrase []byte
	// rootKeyOut is where the root key goes; empty: data_dir/root.key.
	rootKeyOut string
	// keyPassphrase encrypts the keys the server uses; empty: not
	// encrypted.
	keyPassphrase []byte
}

func newInitCommand(configPath *string) *cobra.Command {
	var rootPassphraseFile, rootKeyOut string
	var encryptKeys, externalRoot bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create the CA keys and certificates",
		Long: "Create a new certificate authority in the configured data directory:\n" +
			"a root certificate, an intermediate certificate and the SSH CA keys.\n" +
			"Run this once. It never overwrites an existing CA.\n\n" +
			"The root key is always encrypted with a passphrase, which is asked\n" +
			"here. The server never needs the root key: write it straight to\n" +
			"removable storage with --root-key-out, or move it there afterwards.\n\n" +
			"The keys the server uses are encrypted too if a passphrase for them\n" +
			"is configured (ca.key_passphrase_file, the systemd credential\n" +
			"bastionxp-ca-key-passphrase, " + envKeyPassphraseFile + " or " + envKeyPassphrase + "),\n" +
			"or with --encrypt-keys, which asks for one.",
		Example: "  bxp init --config bastionxp-ca.yaml --root-key-out /media/usb/root.key",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			// Fail before asking for any passphrase.
			rootKeyPath := rootKeyOut
			if rootKeyPath == "" && !externalRoot {
				rootKeyPath = filepath.Join(cfg.DataDir, ca.RootKeyFile)
			}
			if err := ca.CheckNew(cfg.DataDir, rootKeyPath); err != nil {
				return err
			}
			prompt := cmd.ErrOrStderr()
			opts := initOptions{rootKeyOut: rootKeyOut}

			if externalRoot {
				if rootKeyOut != "" || rootPassphraseFile != "" {
					return errors.New("with --external-root there is no root key: leave out --root-key-out and --root-passphrase-file")
				}
				passphrase, err := serverPassphraseForInit(cfg, prompt, encryptKeys)
				if err != nil {
					return err
				}
				return runInitExternal(cmd.OutOrStdout(), cfg, passphrase)
			}
			if rootPassphraseFile != "" {
				opts.rootPassphrase, err = readPassphraseFile(rootPassphraseFile)
				if err == nil {
					err = checkNewPassphrase(string(opts.rootPassphrase))
				}
			} else {
				opts.rootPassphrase, err = askNewPassphrase(prompt, "Passphrase for the root key")
			}
			if err != nil {
				return fmt.Errorf("root key passphrase: %w", err)
			}

			opts.keyPassphrase, err = serverPassphraseForInit(cfg, prompt, encryptKeys)
			if err != nil {
				return err
			}
			return runInit(cmd.OutOrStdout(), cfg, opts)
		},
	}
	cmd.Flags().StringVar(&rootPassphraseFile, "root-passphrase-file", "",
		"read the root key's passphrase from this file instead of asking (/dev/stdin works)")
	cmd.Flags().StringVar(&rootKeyOut, "root-key-out", "",
		"write the root key here, e.g. on removable storage, instead of into data_dir")
	cmd.Flags().BoolVar(&encryptKeys, "encrypt-keys", false,
		"encrypt the keys the server uses; asks for a passphrase if none is configured")
	cmd.Flags().BoolVar(&externalRoot, "external-root", false,
		"under an existing root (e.g. Active Directory Certificate Services): make no root,\n"+
			"but a CSR for the intermediate, for that root's CA to sign")
	return cmd
}

func runInit(out io.Writer, cfg *config.Config, opts initOptions) error {
	if len(opts.rootPassphrase) == 0 {
		return errors.New("the root key needs a passphrase")
	}
	// The server's passphrase is kept near the server. If it were also the
	// root's, finding it would open the offline root key too.
	if bytes.Equal(opts.rootPassphrase, opts.keyPassphrase) {
		return errors.New("use another passphrase for the server's keys than for the root key")
	}
	err := ca.Init(cfg.DataDir, ca.InitOptions{
		Name:                 cfg.CA.Name,
		Organization:         cfg.CA.Organization,
		KeyType:              cfg.CA.KeyType,
		RootPassphrase:       opts.rootPassphrase,
		RootKeyPath:          opts.rootKeyOut,
		KeyPassphrase:        opts.keyPassphrase,
		NameConstraints:      cfg.CA.NameConstraints.CA(),
		RootValidity:         cfg.CA.RootLifetime(),
		IntermediateValidity: cfg.CA.IntermediateLifetime(),
	})
	if err != nil {
		return err
	}
	// The token key too, so that all the server's keys are made, and
	// protected, in one place.
	if _, err := token.LoadOrCreateKey(cfg.DataDir, opts.keyPassphrase); err != nil {
		return err
	}

	// Load it back: this proves the files on disk are usable.
	authority, err := ca.Load(cfg.DataDir, opts.keyPassphrase)
	if err != nil {
		return fmt.Errorf("CA was created but cannot be loaded: %w", err)
	}

	rootKey := opts.rootKeyOut
	if rootKey == "" {
		rootKey = filepath.Join(cfg.DataDir, ca.RootKeyFile)
	}
	root := authority.RootCert()
	in := func(name string) string { return filepath.Join(cfg.DataDir, name) }
	fmt.Fprintf(out, "CA created in %s\n\n", cfg.DataDir)
	fmt.Fprintf(out, "  Root CA:        %s\n", root.Subject.CommonName)
	fmt.Fprintf(out, "  Valid until:    %s\n", root.NotAfter.Format("2006-01-02"))
	fmt.Fprintf(out, "  SHA-256:        %s\n", ca.CertFingerprint(root))
	offline := "To move offline:"
	if opts.rootKeyOut != "" {
		offline = "Offline (never in data_dir):"
	}
	printFileGroups(out, fileGroup{"To hand out (public):", []initFile{
		{in(ca.RootCertFile), "root certificate: install where the CA is trusted"},
		{in(ca.IntermediateCertFile), "intermediate certificate (sent with every certificate)"},
		{in(ca.SSHUserCAPubFile), "SSH user CA: TrustedUserCAKeys on SSH servers"},
		{in(ca.SSHHostCAPubFile), "SSH host CA: @cert-authority in known_hosts"},
	}}, fileGroup{offline, []initFile{
		{rootKey, "root key (encrypted)"},
	}}, fileGroup{serverKeysHeading(len(opts.keyPassphrase) > 0), []initFile{
		{in(ca.IntermediateKeyFile), "signs TLS certificates"},
		{in(ca.SSHUserCAKeyFile), "signs SSH user certificates"},
		{in(ca.SSHHostCAKeyFile), "signs SSH host certificates"},
		{in(token.KeyFile), "signs one-time tokens"},
	}})

	if opts.rootKeyOut == "" {
		fmt.Fprintf(out, "\nThe root key is not needed to run the server. Move %s to offline\n", rootKey)
		fmt.Fprintln(out, "storage, keep a backup, and keep its passphrase in a password manager.")
	} else {
		fmt.Fprintln(out, "\nThe root key never touched data_dir. Keep a backup of it, and its")
		fmt.Fprintln(out, "passphrase in a password manager.")
	}
	fmt.Fprintln(out, "\nClients trust this CA with:")
	fmt.Fprintf(out, "  bxp trust --ca-url <address of this server> --fingerprint %s\n", ca.CertFingerprint(root))
	return nil
}

// serverPassphraseForInit is the passphrase for the server's keys at init:
// a configured one, or one asked for with --encrypt-keys, or none.
func serverPassphraseForInit(cfg *config.Config, prompt io.Writer, encryptKeys bool) ([]byte, error) {
	passphrase, _, err := keyPassphrase(cfg)
	if err != nil {
		return nil, err
	}
	if passphrase == nil && encryptKeys {
		passphrase, err = askNewPassphrase(prompt, "Passphrase for the server's keys")
		if err != nil {
			return nil, fmt.Errorf("server key passphrase: %w", err)
		}
	}
	if passphrase != nil {
		if err := checkNewPassphrase(string(passphrase)); err != nil {
			return nil, fmt.Errorf("server key passphrase: %w", err)
		}
	}
	return passphrase, nil
}

// runInitExternal creates a CA under another root: everything but the
// intermediate certificate, and a CSR for it.
func runInitExternal(out io.Writer, cfg *config.Config, keyPassphrase []byte) error {
	if err := refuseExternalValidity(cfg); err != nil {
		return err
	}
	if _, err := ca.InitExternal(cfg.DataDir, ca.InitOptions{
		Name: cfg.CA.Name, Organization: cfg.CA.Organization, KeyType: cfg.CA.KeyType, KeyPassphrase: keyPassphrase,
	}); err != nil {
		return err
	}
	if _, err := token.LoadOrCreateKey(cfg.DataDir, keyPassphrase); err != nil {
		return err
	}
	in := func(name string) string { return filepath.Join(cfg.DataDir, name) }
	fmt.Fprintf(out, "CA created in %s, waiting for its intermediate certificate.\n", cfg.DataDir)
	printFileGroups(out, fileGroup{"To hand out (public):", []initFile{
		{in(ca.SSHUserCAPubFile), "SSH user CA: TrustedUserCAKeys on SSH servers"},
		{in(ca.SSHHostCAPubFile), "SSH host CA: @cert-authority in known_hosts"},
	}}, fileGroup{"For the root's CA to sign:", []initFile{
		{in(ca.NextIntermediateCSRFile), "CSR for the intermediate"},
	}}, fileGroup{serverKeysHeading(len(keyPassphrase) > 0), []initFile{
		{in(ca.NextIntermediateKeyFile), "the intermediate's key, waiting for its certificate"},
		{in(ca.SSHUserCAKeyFile), "signs SSH user certificates"},
		{in(ca.SSHHostCAKeyFile), "signs SSH host certificates"},
		{in(token.KeyFile), "signs one-time tokens"},
	}})
	fmt.Fprintln(out)
	printCSRSteps(out, cfg, false)
	if !cfg.CA.NameConstraints.CA().IsZero() {
		fmt.Fprintln(out, "\nca.name_constraints are not in the CSR: ask the root's CA to put them into the")
		fmt.Fprintln(out, "certificate. BastionXP CA refuses names outside whatever constraints the chain carries.")
	}
	return nil
}

// initFile is a file "bxp init" made, with what it is for.
type initFile struct {
	path, purpose string
}

// fileGroup is files under one heading.
type fileGroup struct {
	heading string
	files   []initFile
}

// printFileGroups prints groups of files, the paths lined up across all
// of them. A path longer than maxPathWidth is not lined up, so that one
// long path (a root key on removable storage) does not push the rest
// across the screen.
func printFileGroups(out io.Writer, groups ...fileGroup) {
	const maxPathWidth = 40
	width := 0
	for _, g := range groups {
		for _, f := range g.files {
			if len(f.path) <= maxPathWidth {
				width = max(width, len(f.path))
			}
		}
	}
	for _, g := range groups {
		fmt.Fprintf(out, "\n  %s\n", g.heading)
		for _, f := range g.files {
			fmt.Fprintf(out, "    %-*s  %s\n", width, f.path, f.purpose)
		}
	}
}

// serverKeysHeading names the group of the server's private keys, and
// whether they are encrypted.
func serverKeysHeading(encrypted bool) string {
	if encrypted {
		return "Kept by the server (secret, encrypted):"
	}
	return "Kept by the server (secret, not encrypted; " + seeDocs + "):"
}

// refuseExternalValidity refuses ca.intermediate_validity under an external
// root: the CSR cannot carry a lifetime, the root's CA decides it, and a
// setting that does nothing would make people believe it did.
func refuseExternalValidity(cfg *config.Config) error {
	if cfg.CA.IntermediateValidity != "" {
		return errors.New("ca.intermediate_validity does not apply under an external root: " +
			"the root's CA decides the intermediate's lifetime. Remove it from the configuration")
	}
	return nil
}
