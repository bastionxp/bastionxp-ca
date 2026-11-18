// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/bastionxp/bastionxp-ca/internal/api"
	"github.com/bastionxp/bastionxp-ca/internal/ca"
)

// sshOptions are the settings of "bxp ssh".
type sshOptions struct {
	keyFile    string        // path of the SSH public key, ends in .pub
	template   string        // only used without a token; empty: the CA's profile for the login
	principals []string      // empty: all the token allows
	validity   time.Duration // zero: the server's default
	agent      bool          // put the key and certificate into ssh-agent
}

func newSSHCommand() *cobra.Command {
	conn := connection{openBrowser: openBrowser}
	var opts sshOptions

	cmd := &cobra.Command{
		Use:   "ssh",
		Short: "Get an SSH certificate for an existing SSH key",
		Long: "Ask the CA for an SSH certificate for an existing SSH public key and\n" +
			"write it next to the key, where OpenSSH looks for it:\n\n" +
			"  ~/.ssh/id_ed25519.pub   ->  ~/.ssh/id_ed25519-cert.pub\n\n" +
			"Only the public key is sent to the CA. An existing certificate file\n" +
			"is replaced, because SSH certificates are short-lived and renewed often.\n\n" +
			"With --token, the token decides whether this is a user or a host\n" +
			"certificate and which principals (login names or host names) are\n" +
			"allowed. Without one, your browser opens for a login with your\n" +
			"identity provider (or, with --ldap, you give your directory password),\n" +
			"and you get a user certificate with the principals the CA's rules\n" +
			"give you.\n\n" +
			"With --agent, the key and the certificate go into ssh-agent, for as\n" +
			"long as the certificate is valid. Without --key, a new key is made for\n" +
			"it, in memory only: nothing is written to disk.",
		Example: "  # a user certificate for yourself, with a login in the browser\n" +
			"  bxp ssh --ca-url https://ca.example.com:8443 --root root.crt \\\n" +
			"      --key ~/.ssh/id_ed25519.pub\n\n" +
			"  # the same, with an Active Directory password\n" +
			"  bxp ssh --ldap --key ~/.ssh/id_ed25519.pub\n\n" +
			"  # into ssh-agent, with a new key that never touches the disk\n" +
			"  bxp ssh --agent\n\n" +
			"  # a user certificate with a token\n" +
			"  bxp ssh --ca-url https://ca.example.com:8443 --root root.crt \\\n" +
			"      --token $TOKEN --key ~/.ssh/id_ed25519.pub\n\n" +
			"  # a host certificate\n" +
			"  bxp ssh --ca-url https://ca.example.com:8443 --root root.crt \\\n" +
			"      --token $TOKEN --key /etc/ssh/ssh_host_ed25519_key.pub",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSSH(cmd.Context(), cmd.OutOrStdout(), conn, opts)
		},
	}
	addConnectionFlags(cmd, &conn, true)
	cmd.Flags().StringVar(&opts.keyFile, "key", "", "path of the SSH public key, e.g. ~/.ssh/id_ed25519.pub\n(with --agent: optional; without it, a new key is made in memory)")
	cmd.Flags().BoolVar(&opts.agent, "agent", false,
		"put the key and the certificate into ssh-agent (SSH_AUTH_SOCK), until the certificate expires")
	cmd.Flags().StringVar(&opts.template, "profile", "",
		"ssh-user, ssh-host or one of the CA's SSH profiles. Only used without --token: a token already\n"+
			"says which (default: the profile the CA gives people for themselves at this login)")
	cmd.Flags().StringArrayVar(&opts.principals, "principal", nil,
		"a login name or host name for the certificate (repeat for more; default: all the token allows)")
	cmd.Flags().DurationVar(&opts.validity, "validity", 0,
		"how long the certificate should be valid, e.g. 8h (default: decided by the CA)")
	return cmd
}

func runSSH(ctx context.Context, out io.Writer, conn connection, opts sshOptions) error {
	if opts.keyFile == "" {
		if !opts.agent {
			return errors.New("give the SSH public key file with --key, or use --agent")
		}
		return runSSHAgentOnly(ctx, out, conn, opts)
	}
	// OpenSSH finds the certificate of the key "name" in "name-cert.pub".
	base, isPub := strings.CutSuffix(opts.keyFile, ".pub")
	if !isPub {
		return fmt.Errorf("%s: the key file must be the public key, ending in .pub", opts.keyFile)
	}
	certFile := base + "-cert.pub"

	publicKey, err := os.ReadFile(opts.keyFile)
	if err != nil {
		return fmt.Errorf("read SSH public key: %w", err)
	}
	// Catch a wrong file here, before the token is sent anywhere.
	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKey)
	if err != nil {
		return fmt.Errorf("%s is not an SSH public key", opts.keyFile)
	}
	// Open the private key first, if it goes into the agent: a wrong
	// passphrase must not cost a token.
	var private any
	if opts.agent {
		if private, err = readSSHPrivateKey(base, conn.prompt); err != nil {
			return err
		}
	}

	line, err := requestSSHCert(ctx, conn, opts, string(publicKey), parsedKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certFile, []byte(line), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "Certificate:  %s\n", certFile)
	cert, err := parseSSHCert(line)
	if err != nil {
		return err
	}
	printSSHCert(out, cert)
	if opts.agent {
		return addToAgent(out, conn, private, cert)
	}
	return nil
}

// runSSHAgentOnly gets a certificate for a new key, made in memory, and
// puts both into ssh-agent. Nothing is written to disk.
func runSSHAgentOnly(ctx context.Context, out io.Writer, conn connection, opts sshOptions) error {
	// Reach the agent first: without one, there is nowhere to keep the key.
	_, done, err := conn.agent()
	if err != nil {
		return err
	}
	done()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return err
	}
	line, err := requestSSHCert(ctx, conn, opts, string(ssh.MarshalAuthorizedKey(sshPub)), sshPub)
	if err != nil {
		return err
	}
	cert, err := parseSSHCert(line)
	if err != nil {
		return err
	}
	printSSHCert(out, cert)
	return addToAgent(out, conn, private, cert)
}

// requestSSHCert asks the CA for a certificate for the public key.
func requestSSHCert(ctx context.Context, conn connection, opts sshOptions, publicKey string, parsedKey ssh.PublicKey) (string, error) {
	caClient, err := conn.newClient()
	if err != nil {
		return "", err
	}
	req := api.SignSSHRequest{PublicKey: publicKey, Principals: opts.principals}
	if opts.validity != 0 {
		req.Validity = opts.validity.String()
	}
	// If this needs a login, tell the CA which key the token is for.
	// The token then works for this key only.
	oneTime, err := conn.oneTimeToken(ctx, caClient, loginRequest{
		template:       opts.template,
		kind:           "ssh",
		names:          opts.principals,
		keyFingerprint: ca.SSHFingerprint(parsedKey),
	})
	if err != nil {
		return "", err
	}
	resp, err := caClient.SignSSH(ctx, oneTime, req)
	if err != nil {
		return "", err
	}
	return resp.Certificate, nil
}

func printSSHCert(out io.Writer, cert *ssh.Certificate) {
	fmt.Fprintf(out, "Principals:   %s\n", strings.Join(cert.ValidPrincipals, ", "))
	validUntil := time.Unix(int64(cert.ValidBefore), 0)
	fmt.Fprintf(out, "Valid until:  %s\n", validUntil.Local().Format("2006-01-02 15:04 MST"))
}

// readSSHPrivateKey reads the private key file of an SSH key, asking for
// its passphrase if it has one.
func readSSHPrivateKey(path string, prompt io.Writer) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the private key for ssh-agent: %w", err)
	}
	key, err := ssh.ParseRawPrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		passphrase, askErr := askSecret(prompt, "Passphrase of "+path)
		if askErr != nil {
			return nil, fmt.Errorf("%s has a passphrase, and there is no terminal to ask for it", path)
		}
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(passphrase))
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

// addToAgent puts the key with its certificate into ssh-agent, until the
// certificate expires: the agent then drops both by itself.
func addToAgent(out io.Writer, conn connection, private any, cert *ssh.Certificate) error {
	keyring, done, err := conn.agent()
	if err != nil {
		return err
	}
	defer done()
	lifetime := time.Until(time.Unix(int64(cert.ValidBefore), 0))
	if lifetime <= 0 {
		return errors.New("the certificate has expired already")
	}
	err = keyring.Add(agent.AddedKey{
		PrivateKey:   private,
		Certificate:  cert,
		Comment:      "BastionXP CA " + cert.KeyId,
		LifetimeSecs: uint32(lifetime.Seconds()),
	})
	if err != nil {
		return fmt.Errorf("ssh-agent refused the key: %w", err)
	}
	fmt.Fprintln(out, "Added to ssh-agent until the certificate expires.")
	return nil
}

// parseSSHCert reads an SSH certificate from one line of text.
func parseSSHCert(line string) (*ssh.Certificate, error) {
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, err
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("not an SSH certificate")
	}
	return cert, nil
}
