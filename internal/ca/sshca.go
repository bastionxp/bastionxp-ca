// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Replacing an SSH CA key. SSH servers and clients trust the SSH CA keys
// themselves (TrustedUserCAKeys, @cert-authority in known_hosts), so a new
// key must be trusted everywhere before it signs anything. Two steps:
//
//  1. NewSSHCA makes the next key: ssh_user_ca.next.key and .next.pub.
//     The CA still signs with the current key, and publishes both public
//     keys, so administrators can add the new one everywhere.
//  2. ActivateSSHCA makes the next key the current one. The old private
//     key is removed; its public key is kept in data_dir/replaced. After a
//     restart, the CA signs with the new key.
//
// SSH host certificates signed with a replaced host key can still be
// renewed, so hosts move over by themselves.

// Kinds of SSH CA.
const (
	SSHUserCA = "user"
	SSHHostCA = "host"
)

// sshCAFiles returns the key and public key files of a kind of SSH CA.
func sshCAFiles(kind string) (key, pub string, err error) {
	switch kind {
	case SSHUserCA:
		return SSHUserCAKeyFile, SSHUserCAPubFile, nil
	case SSHHostCA:
		return SSHHostCAKeyFile, SSHHostCAPubFile, nil
	default:
		return "", "", fmt.Errorf("unknown SSH CA %q: use %s or %s", kind, SSHUserCA, SSHHostCA)
	}
}

// nextName turns "ssh_user_ca.key" into "ssh_user_ca.next.key".
func nextName(file string) string {
	ext := filepath.Ext(file)
	return strings.TrimSuffix(file, ext) + ".next" + ext
}

// NewSSHCAOptions are the settings for NewSSHCA.
type NewSSHCAOptions struct {
	Name    string // as at Init, for the key's comment
	KeyType string
	// KeyPassphrase encrypts the new key, like the server's other keys.
	KeyPassphrase []byte
}

// NewSSHCA makes the next key of an SSH CA and returns its public key.
func NewSSHCA(dir, kind string, opts NewSSHCAOptions) (ssh.PublicKey, error) {
	keyFile, pubFile, err := sshCAFiles(kind)
	if err != nil {
		return nil, err
	}
	nextKey := filepath.Join(dir, nextName(keyFile))
	if _, err := os.Stat(nextKey); err == nil {
		return nil, fmt.Errorf("there is a next %s CA key already: activate it first", kind)
	}
	key, err := generateKey(opts.KeyType)
	if err != nil {
		return nil, err
	}
	comment := opts.Name + " SSH " + strings.ToUpper(kind[:1]) + kind[1:] + " CA (next)"
	if err := writeSSHCA(dir, nextName(keyFile), nextName(pubFile), key, comment, opts.KeyPassphrase); err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(key.Public())
}

// ActivateSSHCA makes the next key of an SSH CA the current one, after
// checking that it opens with passphrase. It returns the new public key.
func ActivateSSHCA(dir, kind string, passphrase []byte) (ssh.PublicKey, error) {
	keyFile, pubFile, err := sshCAFiles(kind)
	if err != nil {
		return nil, err
	}
	nextKey, nextPub := filepath.Join(dir, nextName(keyFile)), filepath.Join(dir, nextName(pubFile))
	if _, err := os.Stat(nextKey); err != nil {
		return nil, fmt.Errorf("there is no next %s CA key: make one first", kind)
	}
	signer, err := readSSHCA(nextKey, passphrase)
	if err != nil {
		return nil, err
	}
	published, err := readSSHPub(nextPub)
	if err != nil || !bytes.Equal(published.Marshal(), signer.PublicKey().Marshal()) {
		return nil, fmt.Errorf("%s does not match %s", nextPub, nextKey)
	}

	// Keep the old public key, for the record and for renewals.
	replaced := filepath.Join(dir, ReplacedDir)
	if err := os.MkdirAll(replaced, 0o700); err != nil {
		return nil, err
	}
	oldPub, err := os.ReadFile(filepath.Join(dir, pubFile))
	if err != nil {
		return nil, err
	}
	record := filepath.Join(replaced, time.Now().UTC().Format("20060102-150405")+"-"+pubFile)
	if err := writeNewFile(record, oldPub, 0o644); err != nil {
		return nil, err
	}
	// Renaming over the old key removes it.
	if err := os.Rename(nextKey, filepath.Join(dir, keyFile)); err != nil {
		return nil, err
	}
	if err := os.Rename(nextPub, filepath.Join(dir, pubFile)); err != nil {
		return nil, fmt.Errorf("the new %s CA key is in place but its public key is not (%w): move %s to %s by hand",
			kind, err, nextPub, filepath.Join(dir, pubFile))
	}
	return signer.PublicKey(), nil
}

func readSSHPub(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

// loadSSHExtras reads the next public keys, if any, and the replaced host
// keys.
func (c *CA) loadSSHExtras(dir string) error {
	for _, k := range []struct {
		file string
		into *ssh.PublicKey
	}{{nextName(SSHUserCAPubFile), &c.sshUserNext}, {nextName(SSHHostCAPubFile), &c.sshHostNext}} {
		key, err := readSSHPub(filepath.Join(dir, k.file))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		*k.into = key
	}
	files, err := filepath.Glob(filepath.Join(dir, ReplacedDir, "*-"+SSHHostCAPubFile))
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, file := range files {
		key, err := readSSHPub(file)
		if err != nil {
			return err
		}
		c.sshHostReplaced = append(c.sshHostReplaced, key)
	}
	return nil
}

// SSHUserCAPublicKeys returns the keys SSH servers should trust for user
// certificates: the current one, and the next one while there is one.
func (c *CA) SSHUserCAPublicKeys() []ssh.PublicKey {
	return withNext(c.sshUserCA.PublicKey(), c.sshUserNext)
}

// SSHHostCAPublicKeys does the same for host certificates.
func (c *CA) SSHHostCAPublicKeys() []ssh.PublicKey {
	return withNext(c.sshHostCA.PublicKey(), c.sshHostNext)
}

func withNext(current, next ssh.PublicKey) []ssh.PublicKey {
	if next == nil {
		return []ssh.PublicKey{current}
	}
	return []ssh.PublicKey{current, next}
}

// NextSSHCA returns the next key of a kind of SSH CA, or nil.
func (c *CA) NextSSHCA(kind string) ssh.PublicKey {
	if kind == SSHUserCA {
		return c.sshUserNext
	}
	return c.sshHostNext
}

// IsOwnSSHHostCA reports whether key is the host CA key, current or
// replaced: whether a host certificate signed with it may be renewed.
func (c *CA) IsOwnSSHHostCA(key ssh.PublicKey) bool {
	for _, k := range append([]ssh.PublicKey{c.sshHostCA.PublicKey()}, c.sshHostReplaced...) {
		if bytes.Equal(k.Marshal(), key.Marshal()) {
			return true
		}
	}
	return false
}
