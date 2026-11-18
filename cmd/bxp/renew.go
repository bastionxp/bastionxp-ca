// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// renewOptions are the settings of "bxp renew".
type renewOptions struct {
	cert  string // the certificate file to renew
	key   string // its private key
	force bool   // renew even if it is not time yet
	exec  string // a command to run after a renewal
}

func newRenewCommand() *cobra.Command {
	var conn connection
	var opts renewOptions

	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew a certificate before it expires: no token, no login",
		Long: "Renew a TLS certificate, or an SSH host certificate, with the current\n" +
			"certificate and its key as the proof. Nobody has to hand out a token.\n\n" +
			"It does nothing while more than a third of the certificate's lifetime\n" +
			"is left, so run it every hour from a timer: it renews at the right\n" +
			"moment by itself (certificates last 24 hours by default, so daily is\n" +
			"not often enough). The new certificate has the same names as the old one.\n\n" +
			"TLS: a new key is made, and the key and certificate files are replaced.\n" +
			"SSH: the certificate file is replaced; the host key stays the same.\n\n" +
			"A certificate that has expired or was revoked cannot be renewed; it\n" +
			"needs a new one with a token.\n\n" +
			"Only certificates from BastionXP CA's API (\"bxp tls\", a token, a login)\n" +
			"renew this way. Renew one from ACME with the ACME client (\"bxp acme\n" +
			"renew\"), one from SCEP with \"bxp scep renew\".",
		Example: "  bxp renew --cert web.example.com.crt --key web.example.com.key \\\n" +
			"      --exec \"systemctl reload nginx\"\n\n" +
			"  bxp renew --cert /etc/ssh/ssh_host_ed25519_key-cert.pub \\\n" +
			"      --key /etc/ssh/ssh_host_ed25519_key --exec \"systemctl reload sshd\"",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRenew(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), conn, opts)
		},
	}
	cmd.Flags().StringVar(&opts.cert, "cert", "", "the certificate to renew: a TLS .crt file, or an SSH ...-cert.pub file")
	cmd.Flags().StringVar(&opts.key, "key", "", "its private key")
	cmd.Flags().BoolVar(&opts.force, "force", false, "renew now, even if more than a third of the lifetime is left")
	cmd.Flags().StringVar(&opts.exec, "exec", "", "a command to run after a renewal, e.g. \"systemctl reload nginx\"")
	// No --token: the certificate is the proof.
	addConnectionFlags(cmd, &conn, false)
	return cmd
}

func runRenew(ctx context.Context, out, errOut io.Writer, conn connection, opts renewOptions) error {
	if opts.cert == "" || opts.key == "" {
		return errors.New("give the certificate with --cert and its private key with --key")
	}
	data, err := os.ReadFile(opts.cert)
	if err != nil {
		return err
	}

	// What kind of certificate is it?
	var renewed bool
	if block, _ := pem.Decode(data); block != nil && block.Type == "CERTIFICATE" {
		renewed, err = renewTLS(ctx, out, conn, opts, block.Bytes)
	} else if parsed, _, _, _, parseErr := ssh.ParseAuthorizedKey(data); parseErr == nil {
		cert, ok := parsed.(*ssh.Certificate)
		if !ok {
			return fmt.Errorf("%s is an SSH public key, not a certificate", opts.cert)
		}
		renewed, err = renewSSH(ctx, out, conn, opts, cert)
	} else {
		return fmt.Errorf("%s is neither a TLS certificate (PEM) nor an SSH certificate", opts.cert)
	}
	if err != nil || !renewed || opts.exec == "" {
		return err
	}

	// Let the program that uses the certificate pick up the new one.
	fmt.Fprintf(out, "Running:      %s\n", opts.exec)
	if err := runShell(ctx, opts.exec, out, errOut); err != nil {
		return fmt.Errorf("the certificate was renewed, but %q failed: %w", opts.exec, err)
	}
	return nil
}

// renewDue reports whether a certificate should be renewed now: when no
// more than a third of its lifetime is left.
func renewDue(notBefore, notAfter, now time.Time) bool {
	lifetime := notAfter.Sub(notBefore)
	return !now.Before(notBefore.Add(lifetime * 2 / 3))
}

// checkTiming decides whether to go on. It returns false, with a message,
// when it is not time yet, and an error for an expired certificate.
func checkTiming(out io.Writer, notBefore, notAfter time.Time, force bool) (bool, error) {
	now := time.Now()
	if !now.Before(notAfter) {
		return false, fmt.Errorf("the certificate expired on %s and cannot be renewed: get a new one with a token",
			notAfter.Local().Format("2006-01-02 15:04"))
	}
	if !force && !renewDue(notBefore, notAfter, now) {
		when := notBefore.Add(notAfter.Sub(notBefore) * 2 / 3)
		fmt.Fprintf(out, "Not yet:      valid until %s, renews from %s on\n",
			notAfter.Local().Format("2006-01-02 15:04"), when.Local().Format("2006-01-02 15:04"))
		return false, nil
	}
	return true, nil
}

func renewTLS(ctx context.Context, out io.Writer, conn connection, opts renewOptions, der []byte) (bool, error) {
	old, err := x509.ParseCertificate(der)
	if err != nil {
		return false, fmt.Errorf("cannot read %s: %w", opts.cert, err)
	}
	if goOn, err := checkTiming(out, old.NotBefore, old.NotAfter, opts.force); !goOn || err != nil {
		return false, err
	}
	oldKey, err := readPrivateKey(opts.key)
	if err != nil {
		return false, err
	}
	if !sameKey(oldKey.Public(), old.PublicKey) {
		return false, fmt.Errorf("%s is not the key of %s", opts.key, opts.cert)
	}
	if err := checkReplaceable(opts.key, opts.cert); err != nil {
		return false, err
	}
	caClient, err := conn.newClient()
	if err != nil {
		return false, err
	}

	// A new key of the same kind as the old one.
	newKey, err := newKeyLike(oldKey)
	if err != nil {
		return false, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, newKey)
	if err != nil {
		return false, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	resp, err := caClient.RenewX509(ctx, old, oldKey, string(csrPEM))
	if err != nil {
		return false, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(newKey)
	if err != nil {
		return false, err
	}
	// The key first: for a moment the new key sits next to the old
	// certificate, and a program reading both then fails to start and
	// is retried, rather than starting with a mismatched pair silently.
	if err := replaceFile(opts.key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return false, err
	}
	if err := replaceFile(opts.cert, []byte(resp.Chain), 0o644); err != nil {
		return false, err
	}
	fmt.Fprintf(out, "Renewed:      %s\n", opts.cert)
	if notAfter, err := certNotAfter(resp.Certificate); err == nil {
		fmt.Fprintf(out, "Valid until:  %s\n", notAfter.Local().Format("2006-01-02 15:04 MST"))
	}
	return true, nil
}

func renewSSH(ctx context.Context, out io.Writer, conn connection, opts renewOptions, old *ssh.Certificate) (bool, error) {
	if old.CertType != ssh.HostCert {
		return false, errors.New("only SSH host certificates can be renewed; for a user certificate, run \"bxp ssh\" again")
	}
	notBefore, notAfter := time.Unix(int64(old.ValidAfter), 0), time.Unix(int64(old.ValidBefore), 0)
	if goOn, err := checkTiming(out, notBefore, notAfter, opts.force); !goOn || err != nil {
		return false, err
	}
	data, err := os.ReadFile(opts.key)
	if err != nil {
		return false, err
	}
	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return false, fmt.Errorf("cannot read the host key %s: %w", opts.key, err)
	}
	// For ed25519 the SSH library returns a pointer; the rest of Go
	// works with the value.
	if k, ok := raw.(*ed25519.PrivateKey); ok {
		raw = *k
	}
	hostKey, ok := raw.(crypto.Signer)
	if !ok {
		return false, fmt.Errorf("the host key %s cannot sign", opts.key)
	}
	hostPub, err := ssh.NewPublicKey(hostKey.Public())
	if err != nil || !bytes.Equal(hostPub.Marshal(), old.Key.Marshal()) {
		return false, fmt.Errorf("%s is not the key of %s", opts.key, opts.cert)
	}
	if err := checkReplaceable(opts.cert); err != nil {
		return false, err
	}
	caClient, err := conn.newClient()
	if err != nil {
		return false, err
	}

	resp, err := caClient.RenewSSH(ctx, old, hostKey)
	if err != nil {
		return false, err
	}
	if err := replaceFile(opts.cert, []byte(resp.Certificate), 0o644); err != nil {
		return false, err
	}
	fmt.Fprintf(out, "Renewed:      %s\n", opts.cert)
	if cert, err := parseSSHCert(resp.Certificate); err == nil {
		fmt.Fprintf(out, "Valid until:  %s\n", time.Unix(int64(cert.ValidBefore), 0).Local().Format("2006-01-02 15:04 MST"))
	}
	return true, nil
}

// readPrivateKey reads a private key in PEM form: PKCS#8, as BastionXP CA
// writes it, or the older RSA and EC forms other tools write.
func readPrivateKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM private key found", path)
	}
	var key any
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%s: unsupported key type %q", path, block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: this key cannot sign", path)
	}
	return signer, nil
}

// newKeyLike makes a new key of the same kind and size as old, so that a
// renewal never changes what programs using the certificate must support.
func newKeyLike(old crypto.Signer) (crypto.Signer, error) {
	switch k := old.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.GenerateKey(k.Curve, rand.Reader)
	case *rsa.PrivateKey:
		return rsa.GenerateKey(rand.Reader, k.N.BitLen())
	case ed25519.PrivateKey:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	}
	return nil, fmt.Errorf("unsupported key type %T", old)
}

// replaceFile writes data to path in one step: a program reading the
// file sees either the old content or the new, never half of it.
//
// The new file gets the owner, group and permissions of the old one. The
// program that uses the certificate often runs as its own user, or reads
// the key through its group (a key file of mode 0640, group ssl-cert);
// a new file owned by root with mode 0600 would lock it out at its next
// reload. mode is only used if there is no old file.
func replaceFile(path string, data []byte, mode os.FileMode) error {
	old, err := os.Stat(path)
	if err == nil {
		mode = old.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".new-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // after a successful rename this does nothing
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if old != nil {
		if err := chownLike(tmp, old); err != nil {
			tmp.Close()
			return fmt.Errorf("cannot give the new %s the owner of the old one: %w", path, err)
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// checkReplaceable makes sure the files can be replaced as replaceFile
// does it, before the CA is asked for anything. A renewal whose result
// cannot be saved is no use.
func checkReplaceable(paths ...string) error {
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if err := canChownLike(info); err != nil {
			return fmt.Errorf("%s belongs to another user: run bxp renew as root or as that user (%w)", path, err)
		}
		// A new file is made next to the old one, then renamed.
		probe, err := os.CreateTemp(filepath.Dir(path), ".bxp-write-test-*")
		if err != nil {
			return fmt.Errorf("cannot write in %s, so the files cannot be replaced: %w", filepath.Dir(path), err)
		}
		probe.Close()
		os.Remove(probe.Name())
	}
	return nil
}

// runShell runs a command line with the system's shell.
func runShell(ctx context.Context, command string, out, errOut io.Writer) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}
	cmd.Stdout, cmd.Stderr = out, errOut
	return cmd.Run()
}

// sameKey reports whether two public keys are the same key.
func sameKey(a, b crypto.PublicKey) bool {
	type equaler interface {
		Equal(crypto.PublicKey) bool
	}
	ka, ok := a.(equaler)
	return ok && ka.Equal(b)
}
