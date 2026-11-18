// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
)

func newProfilesCommand(configPath *string) *cobra.Command {
	var bases bool
	cmd := &cobra.Command{
		Use:   "profiles [name]",
		Short: "Show what each certificate profile contains",
		Long: "Show the certificate profiles: the built-in ones and the ones in\n" +
			"the configuration, with the values they end up with (a profile's base,\n" +
			"with its own settings applied). The values are computed by the same code\n" +
			"the CA uses. Give a name to see one.\n\n" +
			"With --bases, show the six bases a profile can start from, four X.509\n" +
			"and two SSH, without needing a configuration file.\n\n" +
			"It reads only the configuration file: no keys, no CA.",
		Example: "  bxp profiles --config bastionxp-ca.yaml\n" +
			"  bxp profiles --config bastionxp-ca.yaml device-client\n" +
			"  bxp profiles --bases",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if bases {
				if len(args) > 0 {
					return errors.New("give a name or --bases, not both")
				}
				for i, name := range ca.ProfileBases() {
					t, _ := ca.ProfileBase(name, name)
					if i > 0 {
						fmt.Fprintln(out)
					}
					printX509Template(out, t, "base")
				}
				for _, t := range []ca.SSHTemplate{ca.SSHUser, ca.SSHHost} {
					fmt.Fprintln(out)
					printSSHTemplate(out, t, "base, SSH")
				}
				return nil
			}
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			name := ""
			if len(args) == 1 {
				name = args[0]
			}
			return runProfiles(out, cfg, name)
		},
	}
	cmd.Flags().BoolVar(&bases, "bases", false, "show the bases a profile can start from")
	return cmd
}

// runProfiles shows the templates, or the one called name.
func runProfiles(out io.Writer, cfg *config.Config, name string) error {
	profiles, err := cfg.X509Profiles()
	if err != nil {
		return err
	}
	type entry struct {
		show func()
		name string
	}
	var entries []entry
	for _, t := range []ca.X509Template{ca.TLSServer, ca.TLSClient, ca.TLSDevice} {
		label := "built-in"
		if t.Base != t.Name {
			label += ", base " + t.Base
		}
		entries = append(entries, entry{func() { printX509Template(out, t, label) }, t.Name})
	}
	for _, t := range []ca.SSHTemplate{ca.SSHUser, ca.SSHHost} {
		entries = append(entries, entry{func() { printSSHTemplate(out, t, "built-in, SSH") }, t.Name})
	}
	for _, t := range profiles {
		entries = append(entries, entry{func() { printX509Template(out, t, "profile, base "+t.Base) }, t.Name})
	}
	sshProfiles, err := cfg.SSHProfiles()
	if err != nil {
		return err
	}
	for _, t := range sshProfiles {
		entries = append(entries, entry{func() { printSSHTemplate(out, t, "profile, base "+t.Base) }, t.Name})
	}

	if name != "" {
		var names []string
		for _, e := range entries {
			if e.name == name {
				e.show()
				return nil
			}
			names = append(names, e.name)
		}
		return fmt.Errorf("no profile %q: there are %s", name, strings.Join(names, ", "))
	}
	for i, e := range entries {
		if i > 0 {
			fmt.Fprintln(out)
		}
		e.show()
	}
	return nil
}

func printX509Template(out io.Writer, t ca.X509Template, kind string) {
	fmt.Fprintf(out, "%s  (%s)\n", t.Name, kind)
	line := func(label, value string) { fmt.Fprintf(out, "  %-12s %s\n", label+":", value) }

	line("Usage", joinOr(extKeyUsageNames(t.ExtKeyUsage), "none"))
	if t.KeyUsage == 0 {
		line("Key usage", "digital signature; key encipherment too for RSA keys")
	} else {
		line("Key usage", keyUsageNames(t.KeyUsage))
	}
	line("Lifetime", fmt.Sprintf("%s (max %s)", lifetime(t.DefaultValidity), lifetime(t.MaxValidity)))

	subject := "O from the CA"
	if len(t.OrganizationalUnit) > 0 {
		subject += ", OU=" + strings.Join(t.OrganizationalUnit, ", OU=")
	}
	if t.RequireCommonName {
		subject += "; a common name is required"
	}
	line("Subject", subject)

	var names []string
	switch n := t.Names; {
	case n == nil:
		names = []string{"DNS names", "IP addresses", "email addresses"}
	default:
		if n.DNS {
			names = append(names, "DNS names")
			if n.Wildcard {
				names = append(names, "wildcards")
			}
		}
		if n.IP {
			names = append(names, "IP addresses")
		}
		if n.Email {
			names = append(names, "email addresses")
		}
	}
	nameLine := joinOr(names, "none")
	if t.RequireHostName {
		nameLine += "; at least one DNS name or IP address"
	}
	line("Names", nameLine)

	if k := t.Keys; k != nil {
		var rules []string
		if len(k.Algorithms) > 0 {
			rules = append(rules, "only "+strings.Join(k.Algorithms, ", "))
		}
		if k.MinRSABits > 0 {
			rules = append(rules, fmt.Sprintf("RSA at least %d bits", k.MinRSABits))
		}
		if len(k.Curves) > 0 {
			rules = append(rules, "curves "+strings.Join(k.Curves, ", "))
		}
		line("Keys", joinWith(rules, "; ", "any the CA accepts"))
	} else {
		line("Keys", "any the CA accepts (ECDSA P-256/384/521, RSA 2048+, Ed25519)")
	}
	for _, p := range t.Policies {
		line("Policy", p.String())
	}
	for _, e := range t.Extensions {
		critical := ""
		if e.Critical {
			critical = " (critical)"
		}
		line("Extension", e.Id.String()+critical+": "+describeDER(e.Value))
	}
}

func printSSHTemplate(out io.Writer, t ca.SSHTemplate, kind string) {
	fmt.Fprintf(out, "%s  (%s)\n", t.Name, kind)
	line := func(label, value string) { fmt.Fprintf(out, "  %-12s %s\n", label+":", value) }
	certKind := "host certificate: host names"
	if t.CertType == ssh.UserCert {
		certKind = "user certificate: login names"
	}
	line("Kind", certKind)
	line("Lifetime", fmt.Sprintf("%s (max %s)", lifetime(t.DefaultValidity), lifetime(t.MaxValidity)))
	if len(t.Extensions) > 0 {
		var ext []string
		for e := range t.Extensions {
			ext = append(ext, e)
		}
		slices.Sort(ext)
		line("Allows", strings.Join(ext, ", "))
	} else if t.CertType == ssh.UserCert {
		line("Allows", "nothing (no extensions)")
	}
	if len(t.CriticalOptions) > 0 {
		var opts []string
		for o, v := range t.CriticalOptions {
			if v != "" {
				o += "=" + v
			}
			opts = append(opts, o)
		}
		slices.Sort(opts)
		line("Restricts", strings.Join(opts, ", "))
	}
}

var extKeyUsageText = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageServerAuth:      "server auth",
	x509.ExtKeyUsageClientAuth:      "client auth",
	x509.ExtKeyUsageEmailProtection: "email protection",
	x509.ExtKeyUsageCodeSigning:     "code signing",
	x509.ExtKeyUsageTimeStamping:    "time stamping",
	x509.ExtKeyUsageOCSPSigning:     "OCSP signing",
}

func extKeyUsageNames(usages []x509.ExtKeyUsage) []string {
	var out []string
	for _, u := range usages {
		if text, ok := extKeyUsageText[u]; ok {
			out = append(out, text)
		} else {
			out = append(out, fmt.Sprintf("usage %d", u))
		}
	}
	return out
}

func keyUsageNames(u x509.KeyUsage) string {
	var out []string
	for _, k := range []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digital signature"},
		{x509.KeyUsageContentCommitment, "content commitment"},
		{x509.KeyUsageKeyEncipherment, "key encipherment"},
		{x509.KeyUsageDataEncipherment, "data encipherment"},
		{x509.KeyUsageKeyAgreement, "key agreement"},
	} {
		if u&k.bit != 0 {
			out = append(out, k.name)
		}
	}
	return strings.Join(out, ", ")
}

// lifetime writes a duration as people say it: "365 days", "16 hours".
func lifetime(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		return plural(int(d/(24*time.Hour)), "day")
	case d%time.Hour == 0:
		return plural(int(d/time.Hour), "hour")
	default:
		return plural(int(d/time.Minute), "minute")
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

func joinOr(list []string, empty string) string {
	if len(list) == 0 {
		return empty
	}
	return strings.Join(list, ", ")
}

// describeDER shows a DER value: as text if it is a string, otherwise in
// hex.
func describeDER(der []byte) string {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err == nil && raw.Class == asn1.ClassUniversal {
		switch raw.Tag {
		case asn1.TagUTF8String, asn1.TagPrintableString, asn1.TagIA5String:
			return fmt.Sprintf("%q", raw.Bytes)
		case asn1.TagBMPString:
			if len(raw.Bytes)%2 == 0 {
				units := make([]uint16, len(raw.Bytes)/2)
				for i := range units {
					units[i] = uint16(raw.Bytes[2*i])<<8 | uint16(raw.Bytes[2*i+1])
				}
				return fmt.Sprintf("%q", string(utf16.Decode(units)))
			}
		}
	}
	return hex.EncodeToString(der)
}

func joinWith(list []string, sep, empty string) string {
	if len(list) == 0 {
		return empty
	}
	return strings.Join(list, sep)
}
