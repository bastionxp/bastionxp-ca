// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bastionxp/bastionxp-ca/internal/ca"
	"github.com/bastionxp/bastionxp-ca/internal/config"
	"github.com/bastionxp/bastionxp-ca/internal/keyfile"
)

const testKeyPassphrase = "server key passphrase"

// initEncrypted creates a CA whose server keys are encrypted.
func initEncrypted(t *testing.T) *config.Config {
	t.Helper()
	cfg := newTestConfig(t)
	opts := testInit
	opts.keyPassphrase = []byte(testKeyPassphrase)
	if err := runInit(io.Discard, cfg, opts); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func writeSecret(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// bxp init encrypts the root key; without a key passphrase, the server's
// keys stay plain.
func TestInitEncryptsTheRootKey(t *testing.T) {
	cfg := newTestConfig(t)
	if err := runInit(io.Discard, cfg, testInit); err != nil {
		t.Fatal(err)
	}
	rootKey := filepath.Join(cfg.DataDir, ca.RootKeyFile)
	if _, err := keyfile.Read(rootKey, testInit.rootPassphrase); err != nil {
		t.Fatal(err)
	}
	if encrypted, _ := keyfile.IsEncrypted(rootKey); !encrypted {
		t.Error("the root key is not encrypted")
	}
	// Without a key passphrase, the server's keys stay plain.
	if encrypted, _ := keyfile.IsEncrypted(filepath.Join(cfg.DataDir, ca.IntermediateKeyFile)); encrypted {
		t.Error("the intermediate key is encrypted, but no passphrase was given for it")
	}
}

// bxp init refuses to run without a root passphrase or with the same
// passphrase for the root and the server's keys, and creates nothing; a
// short passphrase is refused.
func TestInitRefusals(t *testing.T) {
	same := initOptions{rootPassphrase: []byte("one passphrase"), keyPassphrase: []byte("one passphrase")}
	for name, opts := range map[string]initOptions{
		"no root passphrase": {},
		"same passphrases":   same,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := newTestConfig(t)
			if err := runInit(io.Discard, cfg, opts); err == nil {
				t.Fatal("no error")
			}
			if _, err := os.Stat(filepath.Join(cfg.DataDir, ca.RootCertFile)); err == nil {
				t.Error("a CA was created anyway")
			}
		})
	}
	if err := checkNewPassphrase("short"); err == nil {
		t.Error("a short passphrase was accepted")
	}
}

// bxp init with --root-key-out writes the root key there, encrypted, and not
// into the data directory.
func TestInitRootKeyOut(t *testing.T) {
	cfg := newTestConfig(t)
	opts := testInit
	opts.rootKeyOut = filepath.Join(t.TempDir(), "root.key")
	if err := runInit(io.Discard, cfg, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, ca.RootKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("root key in data_dir: %v", err)
	}
	if _, err := keyfile.Read(opts.rootKeyOut, opts.rootPassphrase); err != nil {
		t.Error(err)
	}
}

// Every place the server's passphrase can come from.
func TestServerKeyPassphraseSources(t *testing.T) {
	cfg := initEncrypted(t)
	tests := []struct {
		name   string
		setup  func(t *testing.T, cfg *config.Config)
		source string
	}{
		{"config file", func(t *testing.T, cfg *config.Config) {
			cfg.CA.KeyPassphraseFile = writeSecret(t, testKeyPassphrase+"\n")
		}, "ca.key_passphrase_file"},
		{"systemd credential", func(t *testing.T, cfg *config.Config) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, keyCredential), []byte(testKeyPassphrase), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("CREDENTIALS_DIRECTORY", dir)
		}, "systemd credential"},
		{"file named in the environment", func(t *testing.T, cfg *config.Config) {
			t.Setenv(envKeyPassphraseFile, writeSecret(t, testKeyPassphrase))
		}, envKeyPassphraseFile},
		{"environment", func(t *testing.T, cfg *config.Config) {
			t.Setenv(envKeyPassphrase, testKeyPassphrase)
		}, envKeyPassphrase},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := *cfg
			tt.setup(t, &c)
			keys, err := loadServerKeys(&c, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if !keys.encrypted || !strings.HasPrefix(keys.source, tt.source) {
				t.Errorf("encrypted %v, source %q", keys.encrypted, keys.source)
			}
		})
	}
}

// The passphrase itself does not stay in the environment, where programs
// BastionXP CA starts would inherit it.
func TestKeyPassphraseLeavesTheEnvironment(t *testing.T) {
	cfg := initEncrypted(t)
	t.Setenv(envKeyPassphrase, testKeyPassphrase)
	if _, err := loadServerKeys(cfg, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, ok := os.LookupEnv(envKeyPassphrase); ok {
		t.Errorf("%s is still set", envKeyPassphrase)
	}
}

// The server's key passphrase is refused when none is given for encrypted
// keys, when it is wrong, and when the keys are not encrypted.
func TestServerKeyPassphraseRefusals(t *testing.T) {
	encrypted := initEncrypted(t)
	plain := newTestConfig(t)
	if err := runInit(io.Discard, plain, testInit); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		cfg  *config.Config
		env  string
		want string
	}{
		// In tests there is no terminal to ask on.
		{"none given", encrypted, "", "the server's keys are encrypted"},
		{"wrong one", encrypted, "not the passphrase", "wrong passphrase"},
		{"keys not encrypted", plain, testKeyPassphrase, "not encrypted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				t.Setenv(envKeyPassphrase, tt.env)
			}
			_, err := loadServerKeys(tt.cfg, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

// The whole road with encrypted keys: serve, a token on the CA machine,
// a certificate.
func TestServeWithEncryptedKeys(t *testing.T) {
	cfg := initEncrypted(t)
	cfg.CA.KeyPassphraseFile = writeSecret(t, testKeyPassphrase)
	url := serveForTest(t, cfg)
	testCA := &testCA{cfg: cfg, url: url, root: filepath.Join(cfg.DataDir, ca.RootCertFile)}
	conn := testCA.connection(t, "tls-server", "web.example.com")
	if err := runTLS(t.Context(), io.Discard, conn, tlsOptions{names: []string{"web.example.com"}, outDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
}

// The startup log says which keys are encrypted. The passphrase "bxp init"
// asks for is the root key's, so the log says so when the server's keys
// are not encrypted.
func TestLogKeyProtection(t *testing.T) {
	const serverKeys = "the server's keys (intermediate CA, SSH CA and token keys)"
	logged := func(t *testing.T, cfg *config.Config) string {
		t.Helper()
		keys, err := loadServerKeys(cfg, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		logKeyProtection(slog.New(slog.NewTextHandler(&out, nil)), cfg, keys)
		return out.String()
	}

	t.Run("root key in data_dir", func(t *testing.T) {
		cfg := newTestConfig(t)
		if err := runInit(io.Discard, cfg, testInit); err != nil {
			t.Fatal(err)
		}
		log := logged(t, cfg)
		if !strings.Contains(log, "the root key is encrypted but "+serverKeys+" are not encrypted; to encrypt them") {
			t.Errorf("log:\n%s", log)
		}
	})

	t.Run("root key offline", func(t *testing.T) {
		cfg := newTestConfig(t)
		opts := testInit
		opts.rootKeyOut = filepath.Join(t.TempDir(), "root.key")
		if err := runInit(io.Discard, cfg, opts); err != nil {
			t.Fatal(err)
		}
		log := logged(t, cfg)
		if !strings.Contains(log, `msg="`+serverKeys+" are not encrypted; to encrypt them") || strings.Contains(log, "root key is encrypted") {
			t.Errorf("log:\n%s", log)
		}
	})

	t.Run("server keys encrypted", func(t *testing.T) {
		cfg := initEncrypted(t)
		cfg.CA.KeyPassphraseFile = writeSecret(t, testKeyPassphrase)
		log := logged(t, cfg)
		if !strings.Contains(log, serverKeys+` are encrypted" passphrase_from=ca.key_passphrase_file`) {
			t.Errorf("log:\n%s", log)
		}
	})
}
