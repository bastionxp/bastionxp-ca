// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	caacme "github.com/bastionxp/bastionxp-ca/internal/acme"
	"github.com/bastionxp/bastionxp-ca/internal/config"
	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// listTimeFormat is how "bxp list" shows times, in the local time zone.
// JSON output uses RFC 3339 in UTC instead.
const listTimeFormat = "2006-01-02 15:04"

func newListCommand(configPath *string) *cobra.Command {
	// "list" names what to list, so that more can come without new
	// top-level commands.
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List what the CA keeps: certificates, ACME accounts and orders",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newListCertificatesCommand(configPath))
	cmd.AddCommand(newListACMEAccountsCommand(configPath))
	cmd.AddCommand(newListACMEOrdersCommand(configPath))
	return cmd
}

// addFormatFlag adds --format to a list command.
func addFormatFlag(cmd *cobra.Command, format *string) {
	cmd.Flags().StringVar(format, "format", "text", "text, or json for scripts and bug reports")
}

func checkFormat(format string) error {
	if format != "text" && format != "json" {
		return fmt.Errorf("unknown --format %q: use text or json", format)
	}
	return nil
}

func writeJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// jsonTime is a time in RFC 3339, UTC, or empty for the zero time.
func jsonTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// --- certificates ---

func newListCertificatesCommand(configPath *string) *cobra.Command {
	var onlyRevoked bool
	var format string
	cmd := &cobra.Command{
		Use:     "certificates",
		Aliases: []string{"certs"},
		Short:   "List the certificates the CA has issued",
		Long: "List the certificates the CA has issued, newest first. Run this on\n" +
			"the CA machine. Certificates stay in the list for 90 days after they\n" +
			"expire.",
		Example: "  bxp list certificates --config bastionxp-ca.yaml\n" +
			"  bxp list certificates --config bastionxp-ca.yaml --revoked\n" +
			"  bxp list certificates --config bastionxp-ca.yaml --format json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkFormat(format); err != nil {
				return err
			}
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			return runListCertificates(cmd.Context(), cmd.OutOrStdout(), cfg, onlyRevoked, format)
		},
	}
	cmd.Flags().BoolVar(&onlyRevoked, "revoked", false, "show only revoked certificates")
	addFormatFlag(cmd, &format)
	return cmd
}

// certificateStatus is "valid", "expired" or "revoked".
func certificateStatus(cert *store.Certificate, now time.Time) string {
	switch {
	case cert.Revoked():
		return "revoked"
	case now.After(cert.NotAfter):
		return "expired"
	default:
		return "valid"
	}
}

type certificateJSON struct {
	Kind      string   `json:"kind"`
	Serial    string   `json:"serial"`
	Profile   string   `json:"profile"`
	Via       string   `json:"via"`
	Subject   string   `json:"subject"`
	Names     []string `json:"names"`
	IssuedAt  string   `json:"issued_at"`
	NotAfter  string   `json:"not_after"`
	Status    string   `json:"status"`
	RevokedAt string   `json:"revoked_at,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

func runListCertificates(ctx context.Context, out io.Writer, cfg *config.Config, onlyRevoked bool, format string) error {
	db, err := openStoreToRead(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	certs, err := db.Certificates(ctx, onlyRevoked)
	if err != nil {
		return err
	}
	now := time.Now()

	if format == "json" {
		list := []certificateJSON{}
		for i := range certs {
			cert := &certs[i]
			c := certificateJSON{
				Kind: cert.Kind, Serial: cert.Serial, Profile: cert.Template, Via: cert.Protocol,
				Subject: cert.Subject, Names: cert.Names,
				IssuedAt: jsonTime(cert.IssuedAt), NotAfter: jsonTime(cert.NotAfter),
				Status: certificateStatus(cert, now), RevokedAt: jsonTime(cert.RevokedAt),
			}
			if c.Names == nil {
				c.Names = []string{}
			}
			if cert.Revoked() {
				c.Reason = reasonName(cert.Reason)
			}
			list = append(list, c)
		}
		return writeJSON(out, list)
	}

	if len(certs) == 0 {
		fmt.Fprintln(out, "No certificates.")
		return nil
	}
	// tabwriter lines the columns up.
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "SERIAL\tPROFILE\tVIA\tNAMES\tVALID UNTIL\tSTATUS")
	for i := range certs {
		cert := &certs[i]
		status := certificateStatus(cert, now)
		if cert.Revoked() {
			status += " " + cert.RevokedAt.Local().Format("2006-01-02") + " (" + reasonName(cert.Reason) + ")"
		}
		via := cert.Protocol
		if via == "" {
			via = "-" // the CA's own
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n",
			cert.Serial, cert.Template, via, describeNames(cert), cert.NotAfter.Local().Format(listTimeFormat), status)
	}
	return table.Flush()
}

// --- ACME accounts ---

func newListACMEAccountsCommand(configPath *string) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "acme-accounts",
		Short: "List the ACME clients that have an account",
		Long: "List the ACME accounts, newest first: each ACME client (certbot, lego,\n" +
			"bxp acme...) that registered with the CA. Run this on the CA machine.",
		Example: "  bxp list acme-accounts --config bastionxp-ca.yaml",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkFormat(format); err != nil {
				return err
			}
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			return runListACMEAccounts(cmd.Context(), cmd.OutOrStdout(), cfg, format)
		},
	}
	addFormatFlag(cmd, &format)
	return cmd
}

type acmeAccountJSON struct {
	ID      string   `json:"id"`
	Status  string   `json:"status"`
	Contact []string `json:"contact"`
	Created string   `json:"created_at"`
}

func runListACMEAccounts(ctx context.Context, out io.Writer, cfg *config.Config, format string) error {
	db, err := openStoreToRead(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	accounts, err := db.ACMEAccounts(ctx)
	if err != nil {
		return err
	}

	if format == "json" {
		list := []acmeAccountJSON{}
		for _, a := range accounts {
			contact := a.Contact
			if contact == nil {
				contact = []string{}
			}
			list = append(list, acmeAccountJSON{ID: a.ID, Status: a.Status, Contact: contact, Created: jsonTime(a.Created)})
		}
		return writeJSON(out, list)
	}

	if len(accounts) == 0 {
		fmt.Fprintln(out, "No ACME accounts.")
		return nil
	}
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "ACCOUNT\tSTATUS\tCREATED\tCONTACT")
	for _, a := range accounts {
		contact := strings.Join(a.Contact, ", ")
		if contact == "" {
			contact = "-"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", a.ID, a.Status, a.Created.Local().Format(listTimeFormat), contact)
	}
	return table.Flush()
}

// --- ACME orders ---

func newListACMEOrdersCommand(configPath *string) *cobra.Command {
	var onlyFailed bool
	var name, format string
	cmd := &cobra.Command{
		Use:   "acme-orders",
		Short: "List the ACME orders, with the proof of each name",
		Long: "List the ACME orders, newest first. Under each order: every name it\n" +
			"asked for, whether the client proved it, with which challenge, and\n" +
			"why a proof failed. Run this on the CA machine.\n\n" +
			"An order is a client's request for one certificate. A client has 24\n" +
			"hours to finish it. Once it has expired, an order is removed when the\n" +
			"next order comes in, except: an order that got a certificate stays while\n" +
			"the certificate is valid, and a failed order is kept for 7 more days, so\n" +
			"that --failed can still show why a client did not get its certificate.",
		Example: "  bxp list acme-orders --config bastionxp-ca.yaml\n" +
			"  # why does a client not get its certificate?\n" +
			"  bxp list acme-orders --config bastionxp-ca.yaml --failed --name web.example.com",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkFormat(format); err != nil {
				return err
			}
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			return runListACMEOrders(cmd.Context(), cmd.OutOrStdout(), cfg, onlyFailed, name, format)
		},
	}
	cmd.Flags().BoolVar(&onlyFailed, "failed", false, "show only orders where a proof failed")
	cmd.Flags().StringVar(&name, "name", "", "show only orders for this name")
	addFormatFlag(cmd, &format)
	return cmd
}

// replacedSerial is the serial number (hex, as "bxp list certificates"
// shows it) in an order's "replaces", or the ID itself if it has none.
func replacedSerial(certID string) string {
	if certID == "" {
		return ""
	}
	if _, serial, err := caacme.ParseCertID(certID); err == nil {
		return store.X509Serial(serial)
	}
	return certID
}

// orderState is the order's ACME status, or "expired" for an order that
// ran out of time before it got its certificate.
func orderState(o *store.ACMEOrderWithAuthzs, now time.Time) string {
	status := o.Status(o.Authzs)
	if (status == store.ACMEPending || status == "ready") && now.After(o.Expires) {
		return "expired"
	}
	return status
}

// hasName reports whether the order asked for name.
func hasName(o *store.ACMEOrderWithAuthzs, name string) bool {
	for _, n := range o.Names {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// acmeError splits the error the CA saved for a failed proof, an ACME
// problem document (RFC 8555 section 6.7) as sent to the client, into its
// kind (e.g. "connection") and its detail.
func acmeError(saved string) (kind, detail string) {
	var p struct {
		Type   string `json:"type"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal([]byte(saved), &p); err != nil || p.Detail == "" {
		return "", saved
	}
	return strings.TrimPrefix(p.Type, "urn:ietf:params:acme:error:"), p.Detail
}

type acmeAuthzJSON struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Challenge string `json:"challenge,omitempty"`
	ErrorType string `json:"error_type,omitempty"`
	Error     string `json:"error,omitempty"`
	Expires   string `json:"expires_at"`
}

type acmeOrderJSON struct {
	ID             string          `json:"id"`
	Account        string          `json:"account_id"`
	State          string          `json:"state"`
	Names          []string        `json:"names"`
	Serial         string          `json:"serial,omitempty"`
	Replaces       string          `json:"replaces,omitempty"` // serial of the certificate it renews
	Expires        string          `json:"expires_at"`
	Authorizations []acmeAuthzJSON `json:"authorizations"`
}

func runListACMEOrders(ctx context.Context, out io.Writer, cfg *config.Config, onlyFailed bool, name, format string) error {
	db, err := openStoreToRead(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	all, err := db.ACMEOrders(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	var orders []store.ACMEOrderWithAuthzs
	for i := range all {
		o := &all[i]
		if onlyFailed && o.Status(o.Authzs) != store.ACMEInvalid {
			continue
		}
		if name != "" && !hasName(o, name) {
			continue
		}
		orders = append(orders, *o)
	}

	if format == "json" {
		list := []acmeOrderJSON{}
		for i := range orders {
			o := &orders[i]
			j := acmeOrderJSON{
				ID: o.ID, Account: o.AccountID, State: orderState(o, now), Names: o.Names,
				Serial: o.Serial, Replaces: replacedSerial(o.Replaces),
				Expires: jsonTime(o.Expires), Authorizations: []acmeAuthzJSON{},
			}
			for _, a := range o.Authzs {
				kind, detail := acmeError(a.Error)
				j.Authorizations = append(j.Authorizations, acmeAuthzJSON{
					Name: a.Name, Status: a.Status, Challenge: a.Challenge,
					ErrorType: kind, Error: detail, Expires: jsonTime(a.Expires),
				})
			}
			list = append(list, j)
		}
		return writeJSON(out, list)
	}

	if len(orders) == 0 {
		fmt.Fprintln(out, "No ACME orders.")
		return nil
	}
	// One block per order: the order, then a line per name.
	for i := range orders {
		o := &orders[i]
		if i > 0 {
			fmt.Fprintln(out)
		}
		line := fmt.Sprintf("Order %s  %s  account %s  expires %s",
			o.ID, orderState(o, now), o.AccountID, o.Expires.Local().Format(listTimeFormat))
		if o.Serial != "" {
			line += "  certificate " + o.Serial
		}
		if o.Replaces != "" {
			line += "  replaces " + replacedSerial(o.Replaces)
		}
		fmt.Fprintln(out, line)
		table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		for _, a := range o.Authzs {
			challenge := a.Challenge
			if challenge == "" {
				challenge = "-"
			}
			if a.Error == "" {
				fmt.Fprintf(table, "  %s\t%s\t%s\n", a.Name, a.Status, challenge)
				continue
			}
			kind, detail := acmeError(a.Error)
			if kind != "" {
				detail = kind + ": " + detail
			}
			fmt.Fprintf(table, "  %s\t%s\t%s\t%s\n", a.Name, a.Status, challenge, detail)
		}
		if err := table.Flush(); err != nil {
			return err
		}
	}
	return nil
}
