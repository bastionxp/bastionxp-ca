// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
	"github.com/bastionxp/bastionxp-ca/internal/token"
)

// profileNames lists the profiles a token can be made for.
const profileNames = "tls-server, tls-client, tls-device, ssh-user, ssh-host, or one of your profiles"

func newTokenCommand(configPath *string) *cobra.Command {
	conn := connection{openBrowser: openBrowser}
	var opts tokenOptions

	cmd := &cobra.Command{
		Use:   "token",
		Short: "Create a one-time token for requesting a certificate",
		Long: "Create a token that allows its holder to request one certificate\n" +
			"with the given names, and hand it to the person or script that needs\n" +
			"the certificate. The token works once and only until it expires.\n\n" +
			"It works in two places:\n\n" +
			"  On the CA machine, where the configuration file is, it makes the\n" +
			"  token itself.\n\n" +
			"  Anywhere else, or with --ca-url, it asks the CA server for one. Your\n" +
			"  browser opens for a login with your identity provider (or, with\n" +
			"  --ldap, you give your directory password), and you\n" +
			"  must be an admin in the CA's configuration. The CA's log records that you\n" +
			"  created the token.",
		Example: "  # on the CA machine\n" +
			"  bxp token --profile tls-server --name web.example.com --name 10.0.0.5\n" +
			"  bxp token --profile tls-client --name alice@example.com --valid-for 1h\n" +
			"  bxp token --profile ssh-user --name deploy --subject alice@example.com\n\n" +
			"  # from an admin's own machine\n" +
			"  bxp token --ca-url https://ca.example.com:8443 --root root.crt \\\n" +
			"      --profile ssh-host --name web1.example.com",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			remote := tokenIsRemote(cmd.Flag("ca-url").Changed, cmd.Flag("config").Changed, *configPath, conn.url)
			if remote {
				return runRemoteToken(cmd.Context(), cmd.OutOrStdout(), conn, opts)
			}
			cfg, err := config.Load(*configPath)
			if err != nil {
				return fmt.Errorf("%w\nRun this on the CA machine, or give the CA server's address with --ca-url to get a token over the network", err)
			}
			return runToken(cmd.OutOrStdout(), cfg, opts)
		},
	}
	// A token cannot be used to make a token, so there is no --token.
	addConnectionFlags(cmd, &conn, false)
	addLoginFlags(cmd, &conn)
	cmd.Flags().StringVar(&opts.template, "profile", ca.TLSServer.Name,
		"certificate profile: "+profileNames)
	cmd.Flags().StringArrayVar(&opts.names, "name", nil,
		"a name the certificate may contain (repeat for more).\n"+
			"TLS: DNS name, IP address or email address.\n"+
			"SSH: login name (ssh-user) or host name (ssh-host)")
	cmd.Flags().StringVar(&opts.subject, "subject", "",
		"who the token is for, e.g. alice@example.com. It is written to the CA's log\n"+
			"and, for SSH, to the SSH server's log at each login (default: the first name)")
	cmd.Flags().DurationVar(&opts.validFor, "valid-for", token.DefaultValidity,
		fmt.Sprintf("how long the token can be used (maximum %s)", token.MaxValidity))
	return cmd
}

// tokenIsRemote decides where "bxp token" gets the token from: from
// the CA server over the network (true), or by making it itself with the
// key on the CA machine (false).
//
//   - --ca-url given: the person asks for the server, so remote.
//   - --config given, or the configuration file is there: this is the
//     CA machine, so local. BXP_CA_URL alone does not change that, so an
//     administrator who has it set for other commands still makes tokens
//     locally on the CA machine.
//   - Otherwise, with an address from BXP_CA_URL: remote.
func tokenIsRemote(urlGiven, configGiven bool, configPath, url string) bool {
	if urlGiven {
		return true
	}
	if configGiven {
		return false
	}
	if _, err := os.Stat(configPath); err == nil {
		return false
	}
	return url != ""
}

// tokenOptions are the settings of "bxp token".
type tokenOptions struct {
	subject  string        // who the token is for; empty: the first name
	template string        // certificate template
	names    []string      // names the certificate may contain
	validFor time.Duration // zero: the default
}

func runToken(out io.Writer, cfg *config.Config, opts tokenOptions) error {
	_, isX509 := cfg.X509Template(opts.template)
	_, isSSH := cfg.SSHTemplate(opts.template)
	if !isX509 && !isSSH {
		return fmt.Errorf("unknown profile %q: use one of %s", opts.template, profileNames)
	}
	if len(opts.names) == 0 {
		return fmt.Errorf("give at least one name with --name")
	}

	// Load the CA too, to check that it exists: a token for a data
	// directory without a CA would be of no use. If the keys are
	// encrypted, this needs their passphrase.
	keys, err := loadServerKeys(cfg, os.Stderr)
	if err != nil {
		return err
	}
	tok, err := token.New(keys.tokenKey).Issue(token.Options{
		Subject:  opts.subject,
		Template: opts.template,
		Names:    opts.names,
		ValidFor: opts.validFor,
	})
	if err != nil {
		return err
	}

	// Print only the token, so the output can be used in a script:
	// TOKEN=$(bxp token --name web.example.com)
	fmt.Fprintln(out, tok)
	return nil
}

// runRemoteToken gets a token from the CA server, after a login with
// the identity provider in the browser. The CA decides whether the person may have it.
func runRemoteToken(ctx context.Context, out io.Writer, conn connection, opts tokenOptions) error {
	if len(opts.names) == 0 {
		return errors.New("give at least one name with --name")
	}
	caClient, err := conn.newClient()
	if err != nil {
		return err
	}

	// A token cannot be used to make a token: this always needs the
	// login. No key is named, because the token is for somebody else's
	// key.
	oneTime, err := conn.login(ctx, caClient, loginRequest{
		template: opts.template,
		names:    opts.names,
		subject:  opts.subject,
		validFor: opts.validFor,
	})
	if err != nil {
		return err
	}

	// Print only the token, so the output can be used in a script.
	fmt.Fprintln(out, oneTime)
	return nil
}
