// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package keyfile

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type equaler interface{ Equal(crypto.PrivateKey) bool }

func testKeys(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]crypto.Signer{"ecdsa": ec, "rsa": rsaKey, "ed25519": ed}
}

// Every key type is written and read back as the same key, plain or
// encrypted with a passphrase, under the right PEM type.
func TestRoundTrip(t *testing.T) {
	for name, key := range testKeys(t) {
		t.Run(name, func(t *testing.T) {
			for _, passphrase := range []string{"", "correct horse battery staple"} {
				data, err := Marshal(key, []byte(passphrase))
				if err != nil {
					t.Fatal(err)
				}
				wantType := "PRIVATE KEY"
				if passphrase != "" {
					wantType = "ENCRYPTED PRIVATE KEY"
				}
				if block, _ := pem.Decode(data); block == nil || block.Type != wantType {
					t.Fatalf("PEM type, want %s", wantType)
				}
				got, err := Parse(data, []byte(passphrase))
				if err != nil {
					t.Fatal(err)
				}
				if !got.(equaler).Equal(key) {
					t.Error("the key read back is another key")
				}
			}
		})
	}
}

// An encrypted key needs a passphrase and the exact one; encrypting the same
// key twice gives different files (random salt and IV).
func TestEncryptedNeedsTheRightPassphrase(t *testing.T) {
	key := testKeys(t)["ecdsa"]
	data, err := Marshal(key, []byte("right"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data, nil); !errors.Is(err, ErrPassphraseNeeded) {
		t.Errorf("no passphrase: %v, want ErrPassphraseNeeded", err)
	}
	for _, wrong := range []string{"wrong", "Right", "right "} {
		if _, err := Parse(data, []byte(wrong)); !errors.Is(err, ErrWrongPassphrase) {
			t.Errorf("%q: %v, want ErrWrongPassphrase", wrong, err)
		}
	}
	// The same key and passphrase give a different file each time.
	again, _ := Marshal(key, []byte("right"))
	if string(again) == string(data) {
		t.Error("two encryptions are identical: salt or IV not random")
	}
}

// A plain key reads with or without a passphrase.
func TestPlainKeyIgnoresThePassphrase(t *testing.T) {
	data, err := Marshal(testKeys(t)["ecdsa"], nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data, []byte("anything")); err != nil {
		t.Error(err)
	}
}

// Whether a key file is encrypted is told without the passphrase.
func TestIsEncrypted(t *testing.T) {
	dir := t.TempDir()
	key := testKeys(t)["ecdsa"]
	for name, passphrase := range map[string]string{"plain": "", "encrypted": "pw"} {
		data, _ := Marshal(key, []byte(passphrase))
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := IsEncrypted(path)
		if err != nil || got != (passphrase != "") {
			t.Errorf("%s: IsEncrypted = %v, %v", name, got, err)
		}
	}
}

// A crafted file must not make us spend gigabytes of memory.
func TestRefusesExpensiveParameters(t *testing.T) {
	salt := make([]byte, 16)
	kdf, _ := asn1.Marshal(scryptParams{Salt: salt, N: 1 << 30, R: 8, P: 1, KeyLength: 32})
	iv, _ := asn1.Marshal(make([]byte, 16))
	params, _ := asn1.Marshal(pbes2Params{
		KeyDerivationFunc: algorithmIdentifier{Algorithm: oidScrypt, Parameters: asn1.RawValue{FullBytes: kdf}},
		EncryptionScheme:  algorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: iv}},
	})
	der, _ := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm:     algorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: params}},
		EncryptedData: make([]byte, 32),
	})
	data := pem.EncodeToMemory(&pem.Block{Type: encryptedType, Bytes: der})
	_, err := Parse(data, []byte("pw"))
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("error = %v, want out of range", err)
	}
}

// Empty files, text, damaged encrypted keys and other things that are not a
// key are errors.
func TestGarbage(t *testing.T) {
	for _, data := range []string{"", "hello", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
		"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"} {
		if _, err := Parse([]byte(data), []byte("pw")); err == nil {
			t.Errorf("%q: no error", data)
		}
	}
}

// OpenSSL reads our files, and we read OpenSSL's: the format is the
// standard one, so administrators can use their usual tools.
func TestOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	dir := t.TempDir()
	passFile := filepath.Join(dir, "pass")
	if err := os.WriteFile(passFile, []byte("s3cret passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("s3cret passphrase")
	openssl := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
			t.Fatalf("openssl %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	for name, key := range testKeys(t) {
		t.Run(name, func(t *testing.T) {
			ours := filepath.Join(dir, name+"-ours.key")
			data, err := Marshal(key, passphrase)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(ours, data, 0o600); err != nil {
				t.Fatal(err)
			}
			openssl("pkey", "-in", ours, "-passin", "file:"+passFile, "-noout")

			plain := filepath.Join(dir, name+"-plain.key")
			plainData, _ := Marshal(key, nil)
			if err := os.WriteFile(plain, plainData, 0o600); err != nil {
				t.Fatal(err)
			}
			for kdf, args := range map[string][]string{
				"scrypt": {"-scrypt"},
				"pbkdf2": {"-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256"},
			} {
				theirs := filepath.Join(dir, name+"-"+kdf+".key")
				openssl(append([]string{"pkcs8", "-topk8", "-in", plain, "-out", theirs, "-passout", "file:" + passFile}, args...)...)
				got, err := Read(theirs, passphrase)
				if err != nil {
					t.Fatalf("%s: %v", kdf, err)
				}
				if !got.(equaler).Equal(key) {
					t.Errorf("%s: another key", kdf)
				}
			}
		})
	}
}
