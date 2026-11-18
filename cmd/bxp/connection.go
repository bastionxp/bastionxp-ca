// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"github.com/bastionxp/bastionxp-ca/internal/client"
)

// This file has what the client commands (tls, ssh, acme, scep and the
// remote use of token) share: how to reach the CA, and how to get the
// one-time token for a request.

// Environment variables that set the defaults of the connection flags.
const (
	envURL   = "BXP_CA_URL"
	envRoot  = "BXP_ROOT"
	envToken = "BXP_TOKEN"
)

// connection is what the client commands need to reach the CA.
type connection struct {
	url   string // e.g. https://ca.example.com:8443
	root  string // path of the CA's root certificate
	token string // a one-time token; empty: log in with the browser

	// Login with a directory password instead of the browser.
	ldap          bool
	ldapUser      string // empty: the name of the person on this machine
	passwordStdin bool   // read the password from the standard input
	// readPassword asks for the password. Tests replace it.
	readPassword func(prompt string) (string, error)

	// agentDial connects to ssh-agent. Nil means SSH_AUTH_SOCK. Tests
	// replace it.
	agentDial func() (net.Conn, error)

	// prompt is where the instructions for a browser login are written.
	// It is not the normal output, so that the output of a command stays
	// usable in a script.
	prompt io.Writer
	// openBrowser opens an address in the person's browser.
	// Tests replace it.
	openBrowser func(url string) error
}

// newClient checks the connection settings and returns a client.
func (c connection) newClient() (*client.Client, error) {
	if c.url == "" {
		return nil, fmt.Errorf("give the CA server's address with --ca-url or %s", envURL)
	}
	return client.New(c.url, c.root)
}

// oneTimeToken returns the token to send with a certificate request.
//
// If the person gave a token, that is it. Otherwise they log in, with
// the identity provider in their browser or with their directory password
// (--ldap), and the CA hands out a token for what they want, if they may
// have it.
func (c connection) oneTimeToken(ctx context.Context, caClient *client.Client, want loginRequest) (string, error) {
	if c.token != "" {
		return c.token, nil
	}
	return c.login(ctx, caClient, want)
}

// login gets a token by logging in: with the directory password if
// --ldap is given, else in the browser.
func (c connection) login(ctx context.Context, caClient *client.Client, want loginRequest) (string, error) {
	if c.ldap {
		return ldapLogin(ctx, c, caClient, want)
	}
	return browserLogin(ctx, c, caClient, want)
}

// addConnectionFlags adds the flags that say how to reach the CA. The
// values can also come from the environment. That is handy in scripts
// and keeps the token out of the shell history.
//
// withToken is false for commands that have no use for a token.
func addConnectionFlags(cmd *cobra.Command, conn *connection, withToken bool) {
	flags := cmd.PersistentFlags()
	flags.StringVar(&conn.url, "ca-url", os.Getenv(envURL),
		"address of the CA server, e.g. https://ca.example.com:8443\n(or "+envURL+"; default: the one saved by \"bxp trust\")")
	flags.StringVar(&conn.root, "root", os.Getenv(envRoot),
		"path of the CA's root certificate, root.crt\n(or "+envRoot+"; default: the one saved by \"bxp trust\")")
	if withToken {
		flags.StringVar(&conn.token, "token", os.Getenv(envToken),
			"a one-time token (or "+envToken+"). Without one, you log in in your browser")
		addLoginFlags(cmd, conn)
	}
	// The instructions for a browser login go to the error output, so
	// that the normal output of a command stays usable in a script.
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		conn.prompt = cmd.ErrOrStderr()
		if err := conn.checkLoginFlags(); err != nil {
			return err
		}
		return conn.useSavedTrust()
	}
}

// addLoginFlags adds the flags of a login with a directory password.
func addLoginFlags(cmd *cobra.Command, conn *connection) {
	flags := cmd.PersistentFlags()
	flags.BoolVar(&conn.ldap, "ldap", false,
		"log in with your directory (Active Directory) username and password instead of the browser")
	flags.StringVar(&conn.ldapUser, "ldap-user", "",
		"the username for --ldap (default: your name on this machine)")
	flags.BoolVar(&conn.passwordStdin, "password-stdin", false,
		"with --ldap, read the password from the standard input instead of asking")
}

// useSavedTrust fills in the address and the root certificate that
// "bxp trust" saved, where the person gave none. A flag or an
// environment variable always wins.
//
// The saved root belongs to the saved address. So it is only used when
// the address is that one: another server would not be trusted with it,
// and should not be.
func (c *connection) useSavedTrust() error {
	saved, err := loadTrust()
	if err != nil || saved == nil {
		return err
	}
	if c.url == "" {
		c.url = saved.URL
	}
	if c.root == "" && strings.TrimRight(c.url, "/") == saved.URL {
		c.root = saved.RootFile
	}
	return nil
}

// agent connects to ssh-agent. Call close when done.
func (c connection) agent() (keyring agent.ExtendedAgent, close func(), err error) {
	dial := c.agentDial
	if dial == nil {
		dial = func() (net.Conn, error) {
			socket := os.Getenv("SSH_AUTH_SOCK")
			if socket == "" {
				return nil, errors.New("no ssh-agent: SSH_AUTH_SOCK is not set (start one with: eval $(ssh-agent))")
			}
			return net.Dial("unix", socket)
		}
	}
	conn, err := dial()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot reach ssh-agent: %w", err)
	}
	return agent.NewClient(conn), func() { conn.Close() }, nil
}

// terminalConfirm returns a function that asks a yes/no question on the
// terminal, or nil if there is no terminal to ask on.
func terminalConfirm(prompt io.Writer) func(question string) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil
	}
	return func(question string) (bool, error) {
		fmt.Fprintf(prompt, "%s [y/N] ", question)
		answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return false, err
		}
		answer = strings.ToLower(strings.TrimSpace(answer))
		return answer == "y" || answer == "yes", nil
	}
}
