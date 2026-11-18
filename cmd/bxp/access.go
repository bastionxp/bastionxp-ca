// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/bastionxp/bastionxp-ca/internal/config"
	"github.com/bastionxp/bastionxp-ca/internal/policy"
)

func newAccessCommand(configPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "access",
		Short: "See what the access rules give people who log in",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newAccessCheckCommand(configPath))
	return cmd
}

type accessCheckOptions struct {
	user   string
	groups []string
	login  string
	format string
}

func newAccessCheckCommand(configPath *string) *cobra.Command {
	var opts accessCheckOptions
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Show which access rules match a person, and what they may get",
		Long: "Show which rules of \"access:\" in the configuration match a person with\n" +
			"these groups, and what they may then get: whether they may log in, their\n" +
			"SSH principals, their TLS certificate, and whether they are an admin.\n\n" +
			"It reads only the configuration, as the server would after a reload. It\n" +
			"does not ask the identity provider or the directory which groups the\n" +
			"person is in: give them with --group, as they arrive at login (OIDC: the\n" +
			"groups claim, e.g. Entra group IDs; LDAP: the group's name or its DN).",
		Example: "  bxp access check --user alice@corp.example.com --group linux-users --group dba\n" +
			"  bxp access check --login ldap --user alice --group \"Domain Admins\"",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkFormat(opts.format); err != nil {
				return err
			}
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			return runAccessCheck(cmd.OutOrStdout(), cfg, opts)
		},
	}
	cmd.Flags().StringVar(&opts.user, "user", "", "the person's name, as they log in, e.g. alice@corp.example.com")
	cmd.Flags().StringArrayVar(&opts.groups, "group", nil, "a group they are in (repeat for more)")
	cmd.Flags().StringVar(&opts.login, "login", "", "oidc or ldap: whose profiles they get for themselves (default: the one set up)")
	addFormatFlag(cmd, &opts.format)
	return cmd
}

type accessRuleJSON struct {
	Rule          int      `json:"rule"` // from 1, as listed in "access:"
	MatchedBy     string   `json:"matched_by"`
	SSHPrincipals []string `json:"ssh_principals,omitempty"`
	Admin         bool     `json:"admin"`
}

type accessCheckJSON struct {
	User     string           `json:"user"`
	Groups   []string         `json:"groups"`
	Login    string           `json:"login"`
	Rules    []accessRuleJSON `json:"rules"`
	MayLogIn bool             `json:"may_log_in"`
	Admin    bool             `json:"admin"`
	SSH      *ownSSHJSON      `json:"ssh"`
	TLS      *ownTLSJSON      `json:"tls"`
}

type ownSSHJSON struct {
	Profile    string   `json:"profile"`
	Principals []string `json:"principals"`
}

type ownTLSJSON struct {
	Profile string `json:"profile"`
	Name    string `json:"name"`
}

// chooseLogin picks the login method whose profiles apply.
func chooseLogin(cfg *config.Config, login string) (string, error) {
	oidcOn, ldapOn := cfg.OIDC.Issuer != "", cfg.LDAP.Enabled()
	switch login {
	case "oidc", "ldap":
		return login, nil
	case "":
		switch {
		case oidcOn && ldapOn:
			return "", errors.New("both OIDC and LDAP login are set up: say which with --login oidc or --login ldap")
		case ldapOn:
			return "ldap", nil
		default:
			return "oidc", nil
		}
	}
	return "", fmt.Errorf("--login must be oidc or ldap, not %q", login)
}

func runAccessCheck(out io.Writer, cfg *config.Config, opts accessCheckOptions) error {
	if opts.user == "" {
		return errors.New("give the person's name with --user")
	}
	login, err := chooseLogin(cfg, opts.login)
	if err != nil {
		return err
	}
	rules := accessRules(cfg)
	own := loginProfiles(cfg)[login]
	id := policy.Identity{Source: login, Username: opts.user, Groups: opts.groups}

	result := accessCheckJSON{
		User: opts.user, Groups: opts.groups, Login: login, Rules: []accessRuleJSON{},
		MayLogIn: rules.MayLogIn(id), Admin: rules.IsAdmin(id),
	}
	if result.Groups == nil {
		result.Groups = []string{}
	}
	for _, m := range rules.Matches(id) {
		rule := cfg.Access[m.Rule]
		result.Rules = append(result.Rules, accessRuleJSON{
			Rule: m.Rule + 1, MatchedBy: m.By, SSHPrincipals: rule.SSHPrincipals, Admin: rule.Admin,
		})
	}
	if principals := rules.Principals(id); len(principals) > 0 {
		result.SSH = &ownSSHJSON{Profile: own.SSHProfile, Principals: principals}
	}
	if result.MayLogIn && own.X509Profile != "" {
		result.TLS = &ownTLSJSON{Profile: own.X509Profile, Name: opts.user}
	}

	if opts.format == "json" {
		return writeJSON(out, result)
	}

	groups := strings.Join(opts.groups, ", ")
	if groups == "" {
		groups = "-"
	}
	fmt.Fprintf(out, "User:    %s\n", opts.user)
	fmt.Fprintf(out, "Groups:  %s\n", groups)
	fmt.Fprintf(out, "Login:   %s\n", login)
	if !loginEnabled(cfg) {
		fmt.Fprintln(out, "\nNo login is set up (oidc or ldap in the configuration): nobody can log in yet.")
	}

	fmt.Fprintf(out, "\nMatching rules (of %d in \"access:\"):\n", len(cfg.Access))
	if len(result.Rules) == 0 {
		fmt.Fprintln(out, "  none: no rule names this user or one of these groups")
	}
	for _, r := range result.Rules {
		var gives []string
		if len(r.SSHPrincipals) > 0 {
			gives = append(gives, "ssh_principals: "+strings.Join(r.SSHPrincipals, ", "))
		}
		if r.Admin {
			gives = append(gives, "admin")
		}
		if len(gives) == 0 {
			gives = append(gives, "nothing")
		}
		fmt.Fprintf(out, "  #%d  by %s: %s\n", r.Rule, r.MatchedBy, strings.Join(gives, "; "))
	}

	fmt.Fprintln(out, "\nWhat they get:")
	if !result.MayLogIn {
		fmt.Fprintln(out, "  Nothing: a login is refused.")
		return nil
	}
	if result.SSH != nil {
		fmt.Fprintf(out, "  SSH certificate:  %s, for themselves, as %s\n", result.SSH.Profile, strings.Join(result.SSH.Principals, ", "))
	}
	if result.TLS != nil {
		fmt.Fprintf(out, "  TLS certificate:  %s, for %s\n", result.TLS.Profile, result.TLS.Name)
	}
	if result.Admin {
		fmt.Fprintln(out, "  Admin:            one-time tokens for any certificate, for anybody")
	}
	return nil
}
