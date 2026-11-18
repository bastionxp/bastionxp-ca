// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
	"github.com/bastionxp/bastionxp-ca/internal/keyfile"
	"github.com/bastionxp/bastionxp-ca/internal/token"
)

// The passphrase of the keys the server uses (the intermediate key, the
// SSH CA keys and the token key) can come from these places, tried in
// this order:
//
//  1. the file named by ca.key_passphrase_file in the configuration;
//  2. the systemd credential "bastionxp-ca-key-passphrase", for example
//     LoadCredentialEncrypted=bastionxp-ca-key-passphrase:... in the service
//     unit, sealed to the machine's TPM;
//  3. the file named by BXP_KEY_PASSPHRASE_FILE;
//  4. BXP_KEY_PASSPHRASE itself. It is removed from the environment
//     as soon as it is read, so nothing BastionXP CA starts inherits it;
//  5. otherwise it is asked on the terminal, if there is one.
//
// The root key's passphrase never comes from these: it is asked, or read
// from --root-passphrase-file.
const (
	envKeyPassphrase     = "BXP_KEY_PASSPHRASE"
	envKeyPassphraseFile = "BXP_KEY_PASSPHRASE_FILE"
	keyCredential        = "bastionxp-ca-key-passphrase"
)

// minPassphraseLength is the shortest passphrase BastionXP CA accepts for a
// new key.
const minPassphraseLength = 12

// keyPassphrase finds the passphrase of the server's keys without asking.
// It returns nil if none is configured, and says where it came from.
func keyPassphrase(cfg *config.Config) (passphrase []byte, source string, err error) {
	if cfg.CA.KeyPassphraseFile != "" {
		p, err := readPassphraseFile(cfg.CA.KeyPassphraseFile)
		return p, "ca.key_passphrase_file", err
	}
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		path := filepath.Join(dir, keyCredential)
		if _, err := os.Stat(path); err == nil {
			p, err := readPassphraseFile(path)
			return p, "systemd credential " + keyCredential, err
		}
	}
	if path := os.Getenv(envKeyPassphraseFile); path != "" {
		p, err := readPassphraseFile(path)
		return p, envKeyPassphraseFile, err
	}
	if value, ok := os.LookupEnv(envKeyPassphrase); ok {
		os.Unsetenv(envKeyPassphrase)
		if value == "" {
			return nil, envKeyPassphrase, fmt.Errorf("%s is empty", envKeyPassphrase)
		}
		return []byte(value), envKeyPassphrase, nil
	}
	return nil, "", nil
}

// readPassphraseFile reads a passphrase from a file: its first line.
func readPassphraseFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the passphrase: %w", err)
	}
	line, _, _ := strings.Cut(string(data), "\n")
	line = strings.TrimRight(line, "\r")
	if line == "" {
		return nil, fmt.Errorf("the passphrase file %s is empty", path)
	}
	return []byte(line), nil
}

// askSecret asks for a secret on the terminal, without showing it.
func askSecret(prompt io.Writer, label string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("no terminal to ask on")
	}
	fmt.Fprintf(prompt, "%s: ", label)
	secret, err := term.ReadPassword(fd)
	fmt.Fprintln(prompt)
	if err != nil {
		return "", err
	}
	return string(secret), nil
}

// newPassphraseTries is how many times a new passphrase is asked for
// before giving up.
const newPassphraseTries = 3

// askNewPassphrase asks for a new passphrase on the terminal: it says the
// rule first, checks the passphrase as soon as it is typed, then asks for
// it again. A passphrase that is too short or typed differently the second
// time is asked for again, up to newPassphraseTries times.
func askNewPassphrase(prompt io.Writer, label string) ([]byte, error) {
	return askNewPassphraseWith(prompt, label, func(label string) (string, error) {
		return askSecret(prompt, label)
	})
}

// askNewPassphraseWith is askNewPassphrase with the question asked by ask,
// so tests can answer it.
func askNewPassphraseWith(prompt io.Writer, label string, ask func(label string) (string, error)) ([]byte, error) {
	fmt.Fprintf(prompt, "Choose a passphrase of at least %d characters. Keep it safe: it cannot be recovered.\n", minPassphraseLength)
	var lastErr error
	for try := 0; try < newPassphraseTries; try++ {
		first, err := ask(label)
		if err != nil {
			return nil, err
		}
		if err := checkNewPassphrase(first); err != nil {
			lastErr = err
			fmt.Fprintf(prompt, "%s (that one had %d). Try again.\n", capitalize(err.Error()), len([]rune(first)))
			continue
		}
		second, err := ask("Again")
		if err != nil {
			return nil, err
		}
		if first != second {
			lastErr = errors.New("the two passphrases differ")
			fmt.Fprintln(prompt, "The two passphrases differ. Try again.")
			continue
		}
		return []byte(first), nil
	}
	return nil, fmt.Errorf("%w (%d tries)", lastErr, newPassphraseTries)
}

// capitalize makes the first letter of s upper case, to turn an error
// message into a sentence.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func checkNewPassphrase(p string) error {
	if len([]rune(p)) < minPassphraseLength {
		return fmt.Errorf("the passphrase must have at least %d characters", minPassphraseLength)
	}
	return nil
}

// serverKeys are the keys the server uses, opened.
type serverKeys struct {
	ca        *ca.CA
	tokenKey  *ecdsa.PrivateKey
	encrypted bool
	source    string // where the passphrase came from, for the log
	// passphrase opened the keys; nil if they are plain. A new server
	// key is encrypted with it.
	passphrase []byte
}

// loadServerKeys opens the CA and the token key, with the passphrase from
// keyPassphrase, or asked on the terminal if the keys are encrypted and
// none is configured. prompt is where the question goes.
func loadServerKeys(cfg *config.Config, prompt io.Writer) (*serverKeys, error) {
	if waitingForIntermediate(cfg) {
		return nil, fmt.Errorf("%w: have %s signed, then: bxp new-intermediate --import <certificate>",
			ca.ErrWaitingForIntermediate, filepath.Join(cfg.DataDir, ca.NextIntermediateCSRFile))
	}
	encrypted, err := keyfile.IsEncrypted(filepath.Join(cfg.DataDir, ca.IntermediateKeyFile))
	if err != nil {
		return nil, fmt.Errorf("load intermediate key: %w", err)
	}
	passphrase, source, err := keyPassphrase(cfg)
	if err != nil {
		return nil, err
	}
	switch {
	case !encrypted && passphrase != nil:
		// Better to stop than to let someone believe the keys are
		// protected.
		return nil, fmt.Errorf("a key passphrase is given (%s), but the CA keys in %s are not encrypted", source, cfg.DataDir)
	case encrypted && passphrase == nil:
		asked, err := askSecret(prompt, "Passphrase of the CA keys")
		if err != nil {
			return nil, fmt.Errorf("the server's keys are encrypted: give the passphrase with ca.key_passphrase_file, "+
				"the systemd credential %s, %s or %s", keyCredential, envKeyPassphraseFile, envKeyPassphrase)
		}
		passphrase, source = []byte(asked), "terminal"
	}

	authority, err := ca.Load(cfg.DataDir, passphrase)
	if errors.Is(err, keyfile.ErrWrongPassphrase) {
		// Say where the passphrase came from: with several places to
		// look, the wrong one may have been found.
		return nil, fmt.Errorf("the passphrase from %s does not open the server's keys: %w", passphraseSourceName(source), err)
	}
	if err != nil {
		return nil, err
	}
	// The administrator's own profiles; see "profiles" in the
	// configuration.
	profiles, err := cfg.X509Profiles()
	if err != nil {
		return nil, err
	}
	sshProfiles, err := cfg.SSHProfiles()
	if err != nil {
		return nil, err
	}
	authority.SetProfiles(profiles, sshProfiles)
	tokenKey, err := token.LoadOrCreateKey(cfg.DataDir, passphrase)
	if err != nil {
		return nil, err
	}
	return &serverKeys{ca: authority, tokenKey: tokenKey, encrypted: encrypted, source: source, passphrase: passphrase}, nil
}

// passphraseSourceName names where a passphrase came from, for messages.
func passphraseSourceName(source string) string {
	if source == "terminal" {
		return "the terminal"
	}
	return source
}

// waitingForIntermediate reports whether the CA was created under another
// root and its intermediate certificate is not imported yet.
func waitingForIntermediate(cfg *config.Config) bool {
	_, root := os.Stat(filepath.Join(cfg.DataDir, ca.RootCertFile))
	_, csr := os.Stat(filepath.Join(cfg.DataDir, ca.NextIntermediateCSRFile))
	return root != nil && csr == nil
}
