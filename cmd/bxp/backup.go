// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
	"github.com/bastionxp/bastionxp-ca/internal/store"
)

func newBackupCommand(configPath *string) *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Copy the CA's data directory, safely while the server runs",
		Long: "Copy everything in the data directory to a new directory: the keys,\n" +
			"the certificates, and a consistent copy of the database. It is safe\n" +
			"while \"bxp serve\" runs.\n\n" +
			"Keys and database belong together: without the database the CA no\n" +
			"longer knows what it issued, and cannot revoke it.\n\n" +
			"Not in the backup, on purpose: the configuration file, and the\n" +
			"passphrases. Back those up separately. Keep the backup as private as\n" +
			"the data directory: unless the keys are encrypted, it can issue\n" +
			"certificates.\n\n" +
			"To restore: stop the server, put the copy in place of the data\n" +
			"directory (owned by the server's user, mode 700), start the server.",
		Example: "  bxp backup --config /etc/bastionxp-ca/bastionxp-ca.yaml --out /backup/bastionxp-ca-$(date +%F)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			return runBackup(cmd.Context(), cmd.OutOrStdout(), cfg, out)
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "the new directory to write the backup to")
	return cmd
}

func runBackup(ctx context.Context, out io.Writer, cfg *config.Config, dest string) error {
	if dest == "" {
		return errors.New("give the directory for the backup with --out")
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, ca.RootCertFile)); err != nil {
		return fmt.Errorf("no CA in %s: %w", cfg.DataDir, err)
	}
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("%s already exists: give a new directory", dest)
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}

	// The database through SQLite, for a consistent copy; everything
	// else as it is. Read-only and as it is: a backup taken with a newer
	// BastionXP CA, before switching to it, must be of the database before the
	// upgrade. There is none before the server's first start.
	files := 0
	dbPath := filepath.Join(cfg.DataDir, store.FileName)
	if _, err := os.Stat(dbPath); err == nil {
		db, err := store.OpenReadOnly(dbPath)
		if err != nil {
			return err
		}
		defer db.Close()
		if err := db.BackupTo(ctx, filepath.Join(dest, store.FileName)); err != nil {
			return err
		}
		files++
	}
	err := filepath.WalkDir(cfg.DataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(cfg.DataDir, path)
		if err != nil || rel == "." {
			return err
		}
		target := filepath.Join(dest, rel)
		// The database and SQLite's working files are copied above.
		if strings.HasPrefix(d.Name(), store.FileName) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		files++
		return copyFile(path, target, info.Mode().Perm())
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "Backed up %d files from %s to %s\n", files, cfg.DataDir, dest)
	if _, err := os.Stat(filepath.Join(cfg.DataDir, ca.RootKeyFile)); err == nil {
		fmt.Fprintln(out, "It includes the root key (encrypted), which is still in the data directory.")
	}
	fmt.Fprintln(out, "Back up the configuration file and the passphrases separately.")
	return nil
}

func copyFile(from, to string, mode os.FileMode) error {
	src, err := os.Open(from)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	return dst.Close()
}
