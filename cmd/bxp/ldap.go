// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/client"
)

// ldapLogin gets a one-time token by sending the person's directory
// username and password to the CA, which checks them with the directory
// (Active Directory or another LDAP server). See
// internal/server/ldap_login.go for the CA's side.
func ldapLogin(ctx context.Context, conn connection, caClient *client.Client, want loginRequest) (string, error) {
	username := conn.ldapUser
	if username == "" {
		username = currentUsername()
	}
	if username == "" {
		return "", errors.New("give your directory username with --ldap-user")
	}
	password, err := conn.password(username)
	if err != nil {
		return "", err
	}
	if password == "" {
		return "", errors.New("no password given")
	}

	req := api.LDAPLoginRequest{
		Username: username,
		Password: password,
		Template: want.template,
		Kind:     want.kind,
		Names:    want.names,
		Subject:  want.subject,
		Key:      want.keyFingerprint,
	}
	if want.validFor != 0 {
		req.ValidFor = want.validFor.String()
	}
	resp, err := caClient.LDAPLogin(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Token, nil
}

// password asks for the directory password: on the terminal, without
// showing it, or as the first line of the standard input with
// --password-stdin. Never as a flag: flags end up in the shell history
// and in the process list.
func (c connection) password(username string) (string, error) {
	if c.readPassword != nil {
		return c.readPassword(username)
	}
	if c.passwordStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("read the password from the standard input: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	password, err := askSecret(c.prompt, "Password for "+username)
	if err != nil {
		return "", fmt.Errorf("cannot ask for the password (%v): use --password-stdin", err)
	}
	return password, nil
}

// checkLoginFlags catches flags that do not go together.
func (c connection) checkLoginFlags() error {
	if c.ldap && c.token != "" {
		return errors.New("give either --token or --ldap, not both")
	}
	if !c.ldap && (c.ldapUser != "" || c.passwordStdin) {
		return errors.New("--ldap-user and --password-stdin go with --ldap")
	}
	return nil
}

// currentUsername is the name of the person on this machine, without a
// Windows domain ("CORP\alice" gives "alice").
func currentUsername() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	name := u.Username
	if i := strings.LastIndex(name, `\`); i >= 0 {
		name = name[i+1:]
	}
	return name
}
