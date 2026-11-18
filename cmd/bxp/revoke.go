// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// revocationReasons are the reasons "bxp revoke" knows, by the name
// people type.
var revocationReasons = map[string]int{
	"unspecified":    ca.ReasonUnspecified,
	"key-compromise": ca.ReasonKeyCompromise,
	"superseded":     ca.ReasonSuperseded,
	"cessation":      ca.ReasonCessationOfOperation,
}

// reasonNames returns the reasons a person can choose from.
func reasonNames() string {
	var names []string
	for name := range revocationReasons {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// reasonName returns the name of a reason code.
func reasonName(code int) string {
	for name, c := range revocationReasons {
		if c == code {
			return name
		}
	}
	return fmt.Sprintf("reason %d", code)
}

// openStore opens the CA's database. It must exist: opening would create
// an empty one, and an empty list of certificates is not what anybody
// asking about certificates wants to see.
func openStore(cfg *config.Config) (*store.Store, error) {
	path := filepath.Join(cfg.DataDir, store.FileName)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("the CA has no database yet (%s): it is created when \"bxp serve\" first starts", path)
	}
	return store.Open(path)
}

// openStoreToRead opens the CA's database to look only: it is not
// updated to this version's schema, and must already have it.
func openStoreToRead(ctx context.Context, cfg *config.Config) (*store.Store, error) {
	path := filepath.Join(cfg.DataDir, store.FileName)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("the CA has no database yet (%s): it is created when \"bxp serve\" first starts", path)
	}
	db, err := store.OpenReadOnly(path)
	if err != nil {
		return nil, err
	}
	if err := db.CheckVersion(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func newRevokeCommand(configPath *string) *cobra.Command {
	var reason string
	var sshCert bool

	cmd := &cobra.Command{
		Use:   "revoke <serial number>",
		Short: "Revoke a certificate",
		Long: "Declare a TLS certificate invalid before it expires, for example\n" +
			"because its private key may have been stolen. Run this on the CA\n" +
			"machine. The running server notices within 5 seconds: it puts the\n" +
			"certificate on its list of revoked certificates (CRL) and answers\n" +
			"\"revoked\" when asked about it (OCSP). It needs no restart.\n\n" +
			"Find the serial number with \"bxp list certificates\", or in the certificate:\n" +
			"  openssl x509 -in web.crt -noout -serial\n\n" +
			"A revocation cannot be taken back. And it only helps where programs\n" +
			"check for it: " + seeDocs + ".\n\n" +
			"A revoked certificate can no longer be renewed.\n\n" +
			"SSH certificates are revoked with --ssh. That only stops renewal: SSH\n" +
			"servers are not told. To lock someone out at once, remove their\n" +
			"access on the servers.",
		Example: "  bxp revoke 2674c91e0dadae73aaba34dd46d5128c53a49287 --reason key-compromise\n" +
			"  bxp revoke --ssh 5402519870817840555 --reason key-compromise",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			return runRevoke(cmd.Context(), cmd.OutOrStdout(), cfg, args[0], reason, sshCert)
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "unspecified", "why: "+reasonNames())
	cmd.Flags().BoolVar(&sshCert, "ssh", false, "the serial number is that of an SSH certificate (as \"ssh-keygen -L\" shows it)")
	return cmd
}

func runRevoke(ctx context.Context, out io.Writer, cfg *config.Config, serialText, reason string, sshCert bool) error {
	code, ok := revocationReasons[reason]
	if !ok {
		return fmt.Errorf("unknown reason %q: use one of %s", reason, reasonNames())
	}
	kind, kindName, parse := store.KindX509, "TLS", store.ParseX509Serial
	if sshCert {
		kind, kindName, parse = store.KindSSH, "SSH", store.ParseSSHSerial
	}
	serial, err := parse(serialText)
	if err != nil {
		return err
	}
	db, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	cert, err := db.Revoke(ctx, kind, serial, code)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("this CA has no %s certificate with the serial number %s: see \"bxp list certificates\"", kindName, serial)
	case errors.Is(err, store.ErrAlreadyRevoked):
		return fmt.Errorf("the certificate %s was already revoked on %s (%s)",
			serial, cert.RevokedAt.Local().Format("2006-01-02 15:04"), reasonName(cert.Reason))
	case err != nil:
		return err
	}

	fmt.Fprintf(out, "Revoked:  %s\n", cert.Serial)
	fmt.Fprintf(out, "Names:    %s\n", describeNames(cert))
	fmt.Fprintf(out, "Reason:   %s\n", reasonName(cert.Reason))
	fmt.Fprintf(out, "It would have been valid until %s.\n", cert.NotAfter.Local().Format("2006-01-02 15:04 MST"))
	return nil
}

// describeNames returns what a certificate is for, in one short text.
func describeNames(cert *store.Certificate) string {
	names := cert.Names
	if len(names) == 0 && cert.Subject != "" {
		names = []string{cert.Subject}
	}
	text := strings.Join(names, ", ")
	// For SSH the key ID says who, the names say which logins.
	if cert.Kind == store.KindSSH && cert.Subject != "" {
		text = cert.Subject + " (" + text + ")"
	}
	return text
}
