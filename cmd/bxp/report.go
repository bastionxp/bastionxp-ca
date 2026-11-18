// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/bastionxp/bastionxp-ca/internal/config"
	"github.com/bastionxp/bastionxp-ca/internal/store"
)

// "bxp doctor --report" writes one file to attach to a bug report: the
// checks, the configuration as written, and what the database holds, in
// counts. It holds no keys, passphrases, tokens or secrets, and no names of
// people: those are replaced. It does hold host names, addresses and paths,
// which support needs; the file says so at the top.

// reportFailedProofsFor is how far back the report lists failed ACME
// proofs: as long as failed orders are kept.
const reportFailedProofsFor = store.KeepFailedACMEOrdersFor

// reportMaxFailedProofs bounds that list.
const reportMaxFailedProofs = 20

// reportName is the default file name of a report.
func reportName(now time.Time) string {
	return "bastionxp-ca-report-" + now.UTC().Format("20060102-150405") + ".txt"
}

// writeReportHeader starts a report.
func writeReportHeader(w io.Writer, configPath string, now time.Time) {
	fmt.Fprintln(w, "BastionXP CA support report")
	fmt.Fprintf(w, "Created:        %s\n", now.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "bxp:            %s\n", versionText())
	fmt.Fprintf(w, "Configuration:  %s\n\n", configPath)
	fmt.Fprintln(w, "Review this file before you share it. It holds no keys, passphrases,")
	fmt.Fprintln(w, "tokens or secrets, and no names of people: the configuration's users")
	fmt.Fprintln(w, "are replaced, and certificates are only counted. It does hold host")
	fmt.Fprintln(w, "names, addresses and paths of this setup.")
}

func reportSection(w io.Writer, title string) {
	fmt.Fprintf(w, "\n== %s\n\n", title)
}

// writeReportRest writes the sections after the checks. cfg is nil if the
// configuration does not load.
func writeReportRest(ctx context.Context, w io.Writer, configPath string, cfg *config.Config, now time.Time) {
	reportSection(w, "Configuration file (secrets and users replaced, comments removed)")
	if text, err := redactedConfig(configPath); err != nil {
		fmt.Fprintf(w, "cannot read it: %v\n", err)
	} else {
		fmt.Fprint(w, text)
	}
	if cfg == nil {
		return
	}

	db, err := openStoreToRead(ctx, cfg)
	if err != nil {
		reportSection(w, "Database")
		fmt.Fprintln(w, err)
		return
	}
	defer db.Close()
	reportDatabase(ctx, w, cfg, db)
	reportCertificates(ctx, w, db, now)
	reportACME(ctx, w, db, now)
}

// redactedConfig returns the configuration file as written, without
// comments, the OIDC client secret, or the names in access rules.
func redactedConfig(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("not YAML: %w", err)
	}
	users := 0
	redactNode(&doc, nil, &users)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// redactNode walks the YAML tree. path are the keys above n.
func redactNode(n *yaml.Node, path []string, users *int) {
	n.HeadComment, n.LineComment, n.FootComment = "", "", ""
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range n.Content {
			redactNode(child, path, users)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, value := n.Content[i], n.Content[i+1]
			key.HeadComment, key.LineComment, key.FootComment = "", "", ""
			value.HeadComment, value.LineComment, value.FootComment = "", "", ""
			inner := append(append([]string{}, path...), key.Value)
			switch strings.Join(inner, ".") {
			case "oidc.client_secret":
				value.Kind, value.Tag, value.Value, value.Content = yaml.ScalarNode, "!!str", "<removed>", nil
				continue
			case "access.users":
				replaceUsers(value, users)
				continue
			}
			redactNode(value, inner, users)
		}
	}
}

// replaceUsers puts placeholders in place of the names in a users list.
func replaceUsers(n *yaml.Node, users *int) {
	n.HeadComment, n.LineComment, n.FootComment = "", "", ""
	switch n.Kind {
	case yaml.SequenceNode:
		for _, item := range n.Content {
			replaceUsers(item, users)
		}
	case yaml.ScalarNode:
		*users++
		n.Value, n.Tag, n.Style = fmt.Sprintf("<user %d>", *users), "!!str", 0
	}
}

func reportDatabase(ctx context.Context, w io.Writer, cfg *config.Config, db *store.Store) {
	reportSection(w, "Database")
	path := filepath.Join(cfg.DataDir, store.FileName)
	if info, err := os.Stat(path); err == nil {
		fmt.Fprintf(w, "File:            %s (%d KiB)\n", path, info.Size()/1024)
	}
	if v, err := db.Version(ctx); err == nil {
		fmt.Fprintf(w, "Schema version:  %d (this bxp writes %d)\n", v, store.SchemaVersion())
	}
}

func reportCertificates(ctx context.Context, w io.Writer, db *store.Store, now time.Time) {
	reportSection(w, "Certificates (counts only)")
	counts, err := db.CountCertificates(ctx, now)
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}
	if len(counts) == 0 {
		fmt.Fprintln(w, "none")
	} else {
		sort.Slice(counts, func(i, j int) bool {
			if counts[i].Template != counts[j].Template {
				return counts[i].Template < counts[j].Template
			}
			return counts[i].State < counts[j].State
		})
		table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(table, "PROFILE\tSTATE\tCOUNT")
		for _, c := range counts {
			fmt.Fprintf(table, "%s\t%s\t%d\n", c.Template, c.State, c.Count)
		}
		table.Flush()
	}
	if revoked, err := db.RevokedSince(ctx, now.Add(-7*24*time.Hour)); err == nil {
		fmt.Fprintf(w, "\nRevoked in the last 7 days: %d\n", len(revoked))
	}
}

func reportACME(ctx context.Context, w io.Writer, db *store.Store, now time.Time) {
	reportSection(w, "ACME")
	accounts, err := db.ACMEAccounts(ctx)
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}
	accountStates := map[string]int{}
	for _, a := range accounts {
		accountStates[a.Status]++
	}
	fmt.Fprintf(w, "Accounts:  %s\n", countsText(accountStates, len(accounts)))

	orders, err := db.ACMEOrders(ctx)
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}
	orderStates := map[string]int{}
	type failure struct {
		when                     time.Time
		name, challenge, problem string
	}
	var failures []failure
	since := now.Add(-reportFailedProofsFor)
	for i := range orders {
		o := &orders[i]
		orderStates[orderState(o, now)]++
		for _, a := range o.Authzs {
			if a.Status != store.ACMEInvalid || a.Expires.Before(since) {
				continue
			}
			kind, detail := acmeError(a.Error)
			if kind != "" {
				detail = kind + ": " + detail
			}
			failures = append(failures, failure{a.Expires, a.Name, a.Challenge, detail})
		}
	}
	fmt.Fprintf(w, "Orders:    %s\n", countsText(orderStates, len(orders)))

	fmt.Fprintf(w, "\nFailed proofs, newest first (last %d days, at most %d):\n", int(reportFailedProofsFor.Hours()/24), reportMaxFailedProofs)
	if len(failures) == 0 {
		fmt.Fprintln(w, "  none")
		return
	}
	sort.Slice(failures, func(i, j int) bool { return failures[i].when.After(failures[j].when) })
	if len(failures) > reportMaxFailedProofs {
		failures = failures[:reportMaxFailedProofs]
	}
	table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, f := range failures {
		challenge := f.challenge
		if challenge == "" {
			challenge = "-"
		}
		fmt.Fprintf(table, "  %s\t%s\t%s\n", f.name, challenge, f.problem)
	}
	table.Flush()
}

// countsText writes counts by state, e.g. "3 (valid 2, deactivated 1)".
func countsText(states map[string]int, total int) string {
	if total == 0 {
		return "0"
	}
	var parts []string
	for state, n := range states {
		parts = append(parts, fmt.Sprintf("%s %d", state, n))
	}
	sort.Strings(parts)
	return fmt.Sprintf("%d (%s)", total, strings.Join(parts, ", "))
}
