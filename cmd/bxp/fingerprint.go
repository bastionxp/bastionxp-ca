// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
)

func newFingerprintCommand(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "fingerprint",
		Short: "Show the fingerprint of the CA's root certificate",
		Long: "Show the SHA-256 fingerprint of the CA's root certificate: what clients\n" +
			"need for \"bxp trust\". Run this on the CA machine.\n\n" +
			"It reads only the root certificate in the data directory, so it works\n" +
			"while the server is stopped and after root.key has been moved offline.\n\n" +
			"The fingerprint alone goes to the normal output, for scripts:\n" +
			"  FINGERPRINT=$(bxp fingerprint)",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			return runFingerprint(cmd.OutOrStdout(), cmd.ErrOrStderr(), cfg)
		},
	}
}

func runFingerprint(out, hints io.Writer, cfg *config.Config) error {
	root, err := ca.LoadRootCert(cfg.DataDir)
	if err != nil {
		return err
	}
	fingerprint := ca.CertFingerprint(root)
	fmt.Fprintln(out, fingerprint)

	// The line to hand out, on the other output so that scripts get the
	// fingerprint alone.
	address := cfg.Server.URL
	if address == "" {
		address = "<address of this server>"
	}
	fmt.Fprintf(hints, "\nClients trust this CA with:\n  bxp trust --ca-url %s --fingerprint %s\n", address, fingerprint)
	return nil
}
