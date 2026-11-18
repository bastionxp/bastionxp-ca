// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Command bxp is BastionXP CA: the certificate authority server and its client.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// seeDocs ends a message that has more to it than fits in a message.
const seeDocs = "refer to the BastionXP CA documentation for more information"

// version is set at build time with: -ldflags "-X main.version=v1.2.3"
var version = "dev"

// commit and commitTime (RFC 3339) are set at build time where Go cannot
// see the git checkout, as in the container build: -ldflags "-X
// main.commit=<hash> -X main.commitTime=<time>". Elsewhere Go records
// them by itself; see versionText.
var commit, commitTime string

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// The groups of commands in the help.
const (
	groupClient = "client"
	groupCA     = "ca"
)

func newRootCommand() *cobra.Command {
	var configPath string

	root := &cobra.Command{
		Use:           "bxp",
		Short:         "BastionXP CA: the open-source private CA for SSH and TLS certificates",
		Version:       versionText(),
		SilenceUsage:  true, // do not print the help text on every error
		SilenceErrors: true, // main prints the error once
	}
	root.PersistentFlags().StringVar(&configPath, "config", "bastionxp-ca.yaml", "path to the configuration file")

	// Two groups in the help, so that people who only want a certificate
	// see their commands first, apart from those for running the CA.
	root.AddGroup(
		&cobra.Group{ID: groupClient, Title: "Get certificates (on any machine):"},
		&cobra.Group{ID: groupCA, Title: "Run the CA (on the CA machine, or as its admin):"},
	)
	// In the order of use, not alphabetical: trust first on a client,
	// init and serve first on the CA.
	cobra.EnableCommandSorting = false
	add := func(group string, cmds ...*cobra.Command) {
		for _, c := range cmds {
			c.GroupID = group
			root.AddCommand(c)
		}
	}
	add(groupClient,
		newTrustCommand(),
		newTLSCommand(),
		newSSHCommand(),
		newACMECommand(),
		newSCEPCommand(),
		newRenewCommand(),
	)
	add(groupCA,
		newInitCommand(&configPath),
		newServeCommand(&configPath),
		newTokenCommand(&configPath),
		newListCommand(&configPath),
		newRevokeCommand(&configPath),
		newProfilesCommand(&configPath),
		newAccessCommand(&configPath),
		newDoctorCommand(&configPath),
		newBackupCommand(&configPath),
		newFingerprintCommand(&configPath),
		newIntermediateCommand(&configPath),
		newSSHCACommand(&configPath),
	)
	return root
}
