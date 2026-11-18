// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package ca is the certificate authority: it creates the CA keys and signs
// X.509 and SSH certificates.
//
// There is exactly one CA per BastionXP CA instance. It consists of:
//
//   - a root certificate (the trust anchor that clients install),
//   - an intermediate certificate, signed by the root, that signs all
//     X.509 certificates,
//   - an SSH user CA key and an SSH host CA key.
//
// Init creates these once and writes them to a directory. Load reads them
// back. IssueX509 and IssueSSH sign certificates.
//
// This package only signs. Deciding who may get which certificate is the job
// of the verifiers and the policy checks that call into it.
package ca

import (
	"cmp"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bastionxp/bastionxp-ca/internal/keyfile"
)

// File names inside the CA data directory.
const (
	RootCertFile         = "root.crt"
	RootKeyFile          = "root.key"
	IntermediateCertFile = "intermediate.crt"
	IntermediateKeyFile  = "intermediate.key"
	SSHUserCAKeyFile     = "ssh_user_ca.key"
	SSHUserCAPubFile     = "ssh_user_ca.pub"
	SSHHostCAKeyFile     = "ssh_host_ca.key"
	SSHHostCAPubFile     = "ssh_host_ca.pub"
)

const (
	// The lifetimes used when InitOptions and ReplaceOptions give none.
	// The configuration has the same defaults (ca.root_validity,
	// ca.intermediate_validity).
	defaultRootValidity         = 10 * 365 * 24 * time.Hour
	defaultIntermediateValidity = 3 * 365 * 24 * time.Hour

	// backdate is subtracted from "now" when setting a certificate's start
	// time, so machines with a slightly slow clock still accept it.
	backdate = time.Minute
)

// ErrAlreadyInitialized is returned by Init when the directory already holds a CA.
var ErrAlreadyInitialized = errors.New("CA is already initialized")

// CheckNew returns an error if a new CA cannot be created in dir: dir
// already holds a CA (ErrAlreadyInitialized), even a half-created one, or
// a root key is already at rootKeyPath. An empty rootKeyPath skips the
// root key check, for a CA under another root. Init and InitExternal call
// it themselves; "bxp init" also calls it before asking for passphrases.
func CheckNew(dir, rootKeyPath string) error {
	for _, marker := range []string{RootCertFile, NextIntermediateKeyFile, SSHUserCAKeyFile} {
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			return fmt.Errorf("%w in %s", ErrAlreadyInitialized, dir)
		}
	}
	if rootKeyPath != "" {
		if _, err := os.Stat(rootKeyPath); err == nil {
			return fmt.Errorf("%s already exists: the root key is never overwritten", rootKeyPath)
		}
	}
	return nil
}

// InitOptions are the settings for creating a new CA.
type InitOptions struct {
	Name         string // used in certificate names, e.g. "<Name> Root CA"
	Organization string // O field of the CA certificates and all issued certificates
	KeyType      string // KeyTypeECDSA or KeyTypeRSA

	// RootPassphrase encrypts the root key. Empty leaves it unencrypted;
	// "bxp init" always sets one.
	RootPassphrase []byte
	// RootKeyPath is where the root key is written, e.g. on removable
	// storage, so it never touches dir. Empty means dir/root.key.
	RootKeyPath string
	// KeyPassphrase encrypts the keys the server uses: the intermediate
	// key and the SSH CA keys. Empty leaves them unencrypted.
	KeyPassphrase []byte
	// NameConstraints limit the names the intermediate can sign for.
	// Optional; see constraints.go.
	NameConstraints NameConstraints
	// RootValidity and IntermediateValidity are the CA certificates'
	// lifetimes. Zero means the defaults: 10 and 3 years.
	RootValidity, IntermediateValidity time.Duration
}

// CA signs certificates. Create one with Load. It is safe for concurrent use.
type CA struct {
	rootCert         *x509.Certificate
	intermediateCert *x509.Certificate
	intermediateKey  crypto.Signer
	// chain are the CAs between the intermediate and the root, when the
	// root is another CA's. See external.go.
	chain []*x509.Certificate
	// profiles are the administrator's templates; see profiles.go.
	profiles    map[string]X509Template
	sshProfiles map[string]SSHTemplate
	sshUserCA   ssh.Signer
	sshHostCA   ssh.Signer
	// The next SSH CA public keys while a replacement is under way, and
	// the replaced host CA keys. See sshca.go.
	sshUserNext, sshHostNext ssh.PublicKey
	sshHostReplaced          []ssh.PublicKey
	// replacedIntermediates are the intermediates "bxp new-intermediate"
	// replaced; see ReplacedIntermediates.
	replacedIntermediates []*x509.Certificate

	// recorder, if set, is told about every certificate. See Record.
	recorder Recorder
	// publicURL, if set, is written into every X.509 certificate.
	// See PublishAt.
	publicURL string

	// now returns the current time. Tests replace it.
	now func() time.Time
}

// Recorder keeps a list of the certificates the CA has issued. The list
// is what makes it possible to revoke one later, and to say whether a
// certificate is one of ours at all.
type Recorder interface {
	// RecordX509 records a TLS certificate. protocol says how it was
	// obtained (ProtocolAPI, ProtocolACME, ProtocolSCEP), or is empty
	// for the CA's own certificates.
	RecordX509(cert *x509.Certificate, template, protocol string) error
	RecordSSH(cert *ssh.Certificate, template string) error
}

// Record makes the CA tell r about every certificate it issues from now
// on. If r cannot record a certificate, the certificate is not handed
// out: the CA must not issue what it cannot revoke.
//
// Call it once, before the CA is used by several goroutines.
func (c *CA) Record(r Recorder) { c.recorder = r }

// Paths, below the address given to PublishAt, where the CA's public
// information is served.
const (
	RootCertPath         = "/root.crt"
	IntermediateCertPath = "/intermediate.crt"
	CRLPath              = "/crl"
	OCSPPath             = "/ocsp"
)

// PublishAt makes the CA write into every X.509 certificate where the
// information about it can be found: the list of revoked certificates
// (CRL), the service that answers "is this one revoked?" (OCSP), and the
// certificate of the CA that signed it. baseURL is an address such as
// "http://ca.example.com:8080".
//
// Call it once, before the CA is used by several goroutines.
func (c *CA) PublishAt(baseURL string) { c.publicURL = strings.TrimRight(baseURL, "/") }

// Init creates a new CA in dir: root, intermediate and the two SSH CA keys.
// It returns ErrAlreadyInitialized if dir already contains a CA.
func Init(dir string, opts InitOptions) error {
	if opts.Name == "" || opts.Organization == "" {
		return errors.New("CA name and organization are required")
	}
	rootKeyPath := opts.RootKeyPath
	if rootKeyPath == "" {
		rootKeyPath = filepath.Join(dir, RootKeyFile)
	}
	// Check before anything is written, so a mistake leaves nothing behind.
	if err := CheckNew(dir, rootKeyPath); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	now := time.Now()

	// Root: self-signed.
	rootKey, err := generateKey(opts.KeyType)
	if err != nil {
		return fmt.Errorf("generate root key: %w", err)
	}
	rootValidity := cmp.Or(opts.RootValidity, defaultRootValidity)
	intermediateValidity := cmp.Or(opts.IntermediateValidity, defaultIntermediateValidity)
	if intermediateValidity > rootValidity {
		return errors.New("the intermediate cannot be valid for longer than the root")
	}
	rootTemplate, err := caTemplate(opts, "Root CA", now, rootValidity)
	if err != nil {
		return err
	}
	rootTemplate.MaxPathLen = 1 // root -> intermediate -> leaf
	rootCert, err := signCert(rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		return fmt.Errorf("create root certificate: %w", err)
	}

	// Intermediate: signed by the root. It may only sign leaf certificates.
	intermediateKey, err := generateKey(opts.KeyType)
	if err != nil {
		return fmt.Errorf("generate intermediate key: %w", err)
	}
	intermediateTemplate, err := caTemplate(opts, "Intermediate CA", now, intermediateValidity)
	if err != nil {
		return err
	}
	intermediateTemplate.MaxPathLenZero = true
	opts.NameConstraints.apply(intermediateTemplate)
	intermediateCert, err := signCert(intermediateTemplate, rootCert, intermediateKey.Public(), rootKey)
	if err != nil {
		return fmt.Errorf("create intermediate certificate: %w", err)
	}

	// SSH: separate keys for user and host certificates, so that a user
	// certificate can never be mistaken for a host certificate.
	sshUserKey, err := generateKey(opts.KeyType)
	if err != nil {
		return fmt.Errorf("generate SSH user CA key: %w", err)
	}
	sshHostKey, err := generateKey(opts.KeyType)
	if err != nil {
		return fmt.Errorf("generate SSH host CA key: %w", err)
	}

	// Write everything. The root certificate is written last because its
	// presence is what marks the directory as initialized.
	steps := []func() error{
		func() error { return writeKey(rootKeyPath, rootKey, opts.RootPassphrase) },
		func() error {
			return writeKey(filepath.Join(dir, IntermediateKeyFile), intermediateKey, opts.KeyPassphrase)
		},
		func() error { return writeCert(filepath.Join(dir, IntermediateCertFile), intermediateCert) },
		func() error {
			return writeSSHCA(dir, SSHUserCAKeyFile, SSHUserCAPubFile, sshUserKey, opts.Name+" SSH User CA", opts.KeyPassphrase)
		},
		func() error {
			return writeSSHCA(dir, SSHHostCAKeyFile, SSHHostCAPubFile, sshHostKey, opts.Name+" SSH Host CA", opts.KeyPassphrase)
		},
		func() error { return writeCert(filepath.Join(dir, RootCertFile), rootCert) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return fmt.Errorf("write CA files: %w", err)
		}
	}
	return nil
}

// Load reads a CA created by Init. The root private key is not needed and
// not read, so it can be moved offline after Init.
//
// passphrase opens the keys if they are encrypted; nil if they are not.
// Without the right one, the error wraps keyfile.ErrPassphraseNeeded or
// keyfile.ErrWrongPassphrase.
func Load(dir string, passphrase []byte) (*CA, error) {
	rootCert, err := readCert(filepath.Join(dir, RootCertFile))
	if errors.Is(err, os.ErrNotExist) {
		if _, csr := os.Stat(filepath.Join(dir, NextIntermediateCSRFile)); csr == nil {
			return nil, ErrWaitingForIntermediate
		}
	}
	if err != nil {
		return nil, fmt.Errorf("load root certificate: %w", err)
	}
	intermediateCert, err := readCert(filepath.Join(dir, IntermediateCertFile))
	if err != nil {
		return nil, fmt.Errorf("load intermediate certificate: %w", err)
	}
	intermediateKey, err := keyfile.Read(filepath.Join(dir, IntermediateKeyFile), passphrase)
	if err != nil {
		return nil, fmt.Errorf("load intermediate key: %w", err)
	}

	// The CAs between the intermediate and the root, under another root.
	chain, err := readCerts(filepath.Join(dir, ChainFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("load chain: %w", err)
	}

	// Catch mixed-up files early instead of issuing certificates nobody can verify.
	if err := verifiesUpTo(intermediateCert, chain, rootCert); err != nil {
		return nil, fmt.Errorf("intermediate certificate does not chain up to the root: %w", err)
	}
	if !keyMatches(intermediateKey, intermediateCert.PublicKey) {
		return nil, errors.New("intermediate key does not match the intermediate certificate")
	}

	sshUserCA, err := readSSHCA(filepath.Join(dir, SSHUserCAKeyFile), passphrase)
	if err != nil {
		return nil, fmt.Errorf("load SSH user CA key: %w", err)
	}
	sshHostCA, err := readSSHCA(filepath.Join(dir, SSHHostCAKeyFile), passphrase)
	if err != nil {
		return nil, fmt.Errorf("load SSH host CA key: %w", err)
	}

	authority := &CA{
		chain:            chain,
		rootCert:         rootCert,
		intermediateCert: intermediateCert,
		intermediateKey:  intermediateKey,
		sshUserCA:        sshUserCA,
		sshHostCA:        sshHostCA,
		now:              time.Now,
	}
	if err := authority.loadSSHExtras(dir); err != nil {
		return nil, err
	}
	if err := authority.loadReplacedIntermediates(dir); err != nil {
		return nil, err
	}
	return authority, nil
}

// LoadRootCert reads only the root certificate from dir. Unlike Load it
// needs no private key, so it works for a user who may not read the
// keys, and after the CA's keys have been moved elsewhere.
func LoadRootCert(dir string) (*x509.Certificate, error) {
	cert, err := readCert(filepath.Join(dir, RootCertFile))
	if err != nil {
		return nil, fmt.Errorf("load root certificate: %w", err)
	}
	return cert, nil
}

// RootCert returns the root certificate, the trust anchor clients install.
func (c *CA) RootCert() *x509.Certificate { return c.rootCert }

// IntermediateCert returns the certificate that signs all X.509 certificates.
// Servers send it together with their own certificate.
func (c *CA) IntermediateCert() *x509.Certificate { return c.intermediateCert }

// SSHUserCAPublicKey returns the key SSH servers trust for user certificates
// (sshd_config: TrustedUserCAKeys).
func (c *CA) SSHUserCAPublicKey() ssh.PublicKey { return c.sshUserCA.PublicKey() }

// SSHHostCAPublicKey returns the key SSH clients trust for host certificates
// (known_hosts: @cert-authority).
func (c *CA) SSHHostCAPublicKey() ssh.PublicKey { return c.sshHostCA.PublicKey() }

// caTemplate returns the fields shared by the root and intermediate certificates.
func caTemplate(opts InitOptions, role string, now time.Time, validity time.Duration) (*x509.Certificate, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{opts.Organization},
			CommonName:   opts.Name + " " + role,
		},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil
}

// signCert signs template with the parent's key and returns the parsed result.
func signCert(template, parent *x509.Certificate, pub crypto.PublicKey, parentKey crypto.Signer) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// writeSSHCA saves an SSH CA private key and its public key in the
// one-line format that sshd_config and known_hosts use.
func writeSSHCA(dir, keyFile, pubFile string, key crypto.Signer, comment string, passphrase []byte) error {
	if err := writeKey(filepath.Join(dir, keyFile), key, passphrase); err != nil {
		return err
	}
	pub, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		return err
	}
	// MarshalAuthorizedKey returns "<type> <base64>\n"; add the comment before the newline.
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + comment + "\n"
	return writeNewFile(filepath.Join(dir, pubFile), []byte(line), 0o644)
}

func readSSHCA(path string, passphrase []byte) (ssh.Signer, error) {
	key, err := keyfile.Read(path, passphrase)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromSigner(key)
}
