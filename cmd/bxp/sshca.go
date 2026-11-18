// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
)

func newSSHCACommand(configPath *string) *cobra.Command {
	var activate bool
	cmd := &cobra.Command{
		Use:   "new-ssh-ca user|host",
		Short: "Replace an SSH CA key, in two steps",
		Long: "Replace the key of the SSH user CA or the SSH host CA. SSH servers and\n" +
			"clients trust these keys themselves, so a new key must be trusted\n" +
			"everywhere before it signs anything:\n\n" +
			"  1. bxp new-ssh-ca user\n" +
			"     makes the next key. The CA still signs with the current one, and\n" +
			"     /ssh_user_ca.pub lists both. Add the new key everywhere:\n" +
			"     TrustedUserCAKeys on SSH servers (user CA), @cert-authority in\n" +
			"     known_hosts (host CA).\n\n" +
			"  2. bxp new-ssh-ca user --activate\n" +
			"     makes it the current key, and removes the old private key. Restart\n" +
			"     \"bxp serve\". New certificates are signed with the new key.\n\n" +
			"Keep trusting the old key until the certificates it signed have\n" +
			"expired or, for hosts, have been renewed: host certificates signed with\n" +
			"the old key can still be renewed, and come back signed with the new one.\n\n" +
			"Run it on the CA machine. It needs the passphrase of the server's keys,\n" +
			"if they are encrypted, but not the root key.",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{ca.SSHUserCA, ca.SSHHostCA},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			return runNewSSHCA(cmd.OutOrStdout(), cmd.ErrOrStderr(), cfg, args[0], activate)
		},
	}
	cmd.Flags().BoolVar(&activate, "activate", false, "step 2: make the next key the current one")
	return cmd
}

func runNewSSHCA(out, prompt io.Writer, cfg *config.Config, kind string, activate bool) error {
	if kind != ca.SSHUserCA && kind != ca.SSHHostCA {
		return fmt.Errorf("give user or host, not %q", kind)
	}
	// Opens the server's keys: checks the passphrase, which the new key
	// gets too.
	keys, err := loadServerKeys(cfg, prompt)
	if err != nil {
		return err
	}
	where := map[string]string{
		ca.SSHUserCA: "TrustedUserCAKeys on every SSH server",
		ca.SSHHostCA: "the @cert-authority line in known_hosts on every client",
	}[kind]

	if !activate {
		key, err := ca.NewSSHCA(cfg.DataDir, kind, ca.NewSSHCAOptions{
			Name: cfg.CA.Name, KeyType: cfg.CA.KeyType, KeyPassphrase: keys.passphrase,
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Made the next SSH %s CA key. The CA still signs with the current one.\n\n", kind)
		fmt.Fprintf(out, "  %s\n", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
		fmt.Fprintf(out, "  SHA256 fingerprint: %s\n\n", ssh.FingerprintSHA256(key))
		fmt.Fprintf(out, "Add it to %s, next to the current key.\n", where)
		fmt.Fprintf(out, "After a restart of \"bxp serve\", /ssh_%s_ca.pub lists both.\n", kind)
		fmt.Fprintf(out, "Then: bxp new-ssh-ca %s --activate\n", kind)
		return nil
	}

	key, err := ca.ActivateSSHCA(cfg.DataDir, kind, keys.passphrase)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "The SSH %s CA key was replaced: %s\n\n", kind, ssh.FingerprintSHA256(key))
	fmt.Fprintln(out, "Restart \"bxp serve\" to sign with it.")
	fmt.Fprintf(out, "Keep the old key in %s until the certificates it signed have expired", where)
	if kind == ca.SSHHostCA {
		fmt.Fprintln(out, "\nor the hosts have renewed them (bxp renew does it with the old certificate).")
	} else {
		fmt.Fprintln(out, ".")
	}
	return nil
}
