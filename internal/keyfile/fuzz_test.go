// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

package keyfile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"strings"
	"testing"
)

// A file that asks for 4 GiB of scrypt memory with parameters that are each
// within their own limit.
func TestRefusesExpensiveCombination(t *testing.T) {
	kdf, _ := asn1.Marshal(scryptParams{Salt: make([]byte, 16), N: 1 << 20, R: 32, P: 1, KeyLength: 32})
	iv, _ := asn1.Marshal(make([]byte, 16))
	params, _ := asn1.Marshal(pbes2Params{
		KeyDerivationFunc: algorithmIdentifier{Algorithm: oidScrypt, Parameters: asn1.RawValue{FullBytes: kdf}},
		EncryptionScheme:  algorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: iv}},
	})
	der, _ := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm:     algorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: params}},
		EncryptedData: make([]byte, 32),
	})
	_, err := Parse(pem.EncodeToMemory(&pem.Block{Type: encryptedType, Bytes: der}), []byte("pw"))
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Errorf("error = %v, want out of range", err)
	}
}

// FuzzParse feeds arbitrary key files to Parse. It must never panic, and
// what it accepts must be a usable key.
func FuzzParse(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	plain, _ := Marshal(key, nil)
	encrypted, _ := Marshal(key, []byte("pw"))
	f.Add(plain, []byte(""))
	f.Add(encrypted, []byte("pw"))
	f.Add(encrypted, []byte("wrong"))
	f.Add([]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMAA=\n-----END ENCRYPTED PRIVATE KEY-----\n"), []byte("pw"))
	f.Fuzz(func(t *testing.T, data, passphrase []byte) {
		signer, err := Parse(data, passphrase)
		if err == nil && signer.Public() == nil {
			t.Error("accepted a key without a public key")
		}
	})
}
