// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package keyfile reads and writes private key files: PKCS#8 in PEM, plain
// ("PRIVATE KEY") or encrypted with a passphrase ("ENCRYPTED PRIVATE KEY").
//
// Encrypted files use the standard PBES2 scheme (RFC 8018): scrypt makes a
// key from the passphrase, and AES-256-CBC encrypts the PKCS#8 key with it.
// OpenSSL reads and writes the same format:
//
//	openssl pkey -in root.key -noout          # asks for the passphrase
//	openssl pkcs8 -topk8 -scrypt -in plain.key -out encrypted.key
//
// Files that OpenSSL encrypted with PBKDF2 (its default) can be read too.
//
// Encryption protects a key file that is copied away from the machine:
// backups, disk images, a lost USB stick. It does not help if the
// passphrase is copied along, and it does not protect the key on the
// running machine from its administrator.
package keyfile

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"os"

	"golang.org/x/crypto/scrypt"
)

// Errors of Parse.
var (
	// ErrPassphraseNeeded means the key is encrypted and no passphrase
	// was given.
	ErrPassphraseNeeded = errors.New("the key is encrypted: a passphrase is needed")
	// ErrWrongPassphrase means the passphrase does not open the key.
	ErrWrongPassphrase = errors.New("wrong passphrase")
)

// PEM block types.
const (
	plainType     = "PRIVATE KEY"
	encryptedType = "ENCRYPTED PRIVATE KEY"
)

// Object identifiers of the algorithms.
var (
	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidScrypt         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES128CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES256CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// The scrypt cost of new files: about 16 MiB of memory and a tenth of a
// second, twice. Within the limits OpenSSL accepts when it reads a file.
const (
	scryptN = 1 << 14
	scryptR = 8
	scryptP = 2
)

// Limits for files we read, so that a crafted file cannot make us use
// gigabytes of memory or minutes of CPU.
const (
	maxScryptN = 1 << 20
	maxScryptR = 32
	maxScryptP = 16
	// scrypt needs 128*N*r bytes of memory and time in proportion to
	// 128*N*r*p: limit both, not only each parameter. 256 MiB, and about
	// 16 times the cost of our own files.
	maxScryptMemory     = 256 << 20
	maxScryptWork       = 16 * 128 * scryptN * scryptR * scryptP
	maxPBKDF2Iterations = 10_000_000
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type encryptedPrivateKeyInfo struct {
	Algorithm     algorithmIdentifier
	EncryptedData []byte
}

type pbes2Params struct {
	KeyDerivationFunc algorithmIdentifier
	EncryptionScheme  algorithmIdentifier
}

type scryptParams struct {
	Salt      []byte
	N         int
	R         int
	P         int
	KeyLength int `asn1:"optional"`
}

type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int                 `asn1:"optional"`
	PRF        algorithmIdentifier `asn1:"optional"`
}

// Marshal returns key as a PEM file. With a passphrase the key is
// encrypted; with an empty one it is not.
func Marshal(key crypto.Signer, passphrase []byte) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if len(passphrase) == 0 {
		return pem.EncodeToMemory(&pem.Block{Type: plainType, Bytes: der}), nil
	}
	encrypted, err := encrypt(der, passphrase)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: encryptedType, Bytes: encrypted}), nil
}

// Parse reads a PEM key file. An encrypted key needs the passphrase; a
// plain key ignores it.
func Parse(data, passphrase []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM private key found")
	}
	der := block.Bytes
	switch block.Type {
	case plainType:
	case encryptedType:
		if len(passphrase) == 0 {
			return nil, ErrPassphraseNeeded
		}
		var err error
		if der, err = decrypt(block.Bytes, passphrase); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unexpected PEM block %q: want a PKCS#8 private key", block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		if block.Type == encryptedType {
			return nil, ErrWrongPassphrase
		}
		return nil, err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key type %T cannot sign", parsed)
	}
	return signer, nil
}

// Read reads and parses the key file at path. Errors name the file.
func Read(path string, passphrase []byte) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := Parse(data, passphrase)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

// IsEncrypted reports whether the key file at path is encrypted.
func IsEncrypted(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode(data)
	return block != nil && block.Type == encryptedType, nil
}

func encrypt(der, passphrase []byte) ([]byte, error) {
	salt := make([]byte, 16)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	key, err := scrypt.Key(passphrase, salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pad(der)
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, padded)

	kdfParams, err := asn1.Marshal(scryptParams{Salt: salt, N: scryptN, R: scryptR, P: scryptP, KeyLength: 32})
	if err != nil {
		return nil, err
	}
	ivParam, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}
	params, err := asn1.Marshal(pbes2Params{
		KeyDerivationFunc: algorithmIdentifier{Algorithm: oidScrypt, Parameters: asn1.RawValue{FullBytes: kdfParams}},
		EncryptionScheme:  algorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: ivParam}},
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm:     algorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: params}},
		EncryptedData: encrypted,
	})
}

func decrypt(data, passphrase []byte) ([]byte, error) {
	var info encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(data, &info); err != nil || len(rest) > 0 {
		return nil, errors.New("malformed encrypted private key")
	}
	if !info.Algorithm.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("unsupported key encryption %v: only PBES2 is supported", info.Algorithm.Algorithm)
	}
	var params pbes2Params
	if rest, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params); err != nil || len(rest) > 0 {
		return nil, errors.New("malformed PBES2 parameters")
	}

	var keyLen int
	switch alg := params.EncryptionScheme.Algorithm; {
	case alg.Equal(oidAES256CBC):
		keyLen = 32
	case alg.Equal(oidAES128CBC):
		keyLen = 16
	default:
		return nil, fmt.Errorf("unsupported cipher %v: use AES-CBC", alg)
	}
	var iv []byte
	if rest, err := asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil || len(rest) > 0 || len(iv) != aes.BlockSize {
		return nil, errors.New("malformed cipher parameters")
	}

	key, err := deriveKey(params.KeyDerivationFunc, passphrase, keyLen)
	if err != nil {
		return nil, err
	}
	if len(info.EncryptedData) == 0 || len(info.EncryptedData)%aes.BlockSize != 0 {
		return nil, errors.New("malformed encrypted data")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(info.EncryptedData))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, info.EncryptedData)
	// Wrong padding almost always means a wrong passphrase.
	unpadded, ok := unpad(plain)
	if !ok {
		return nil, ErrWrongPassphrase
	}
	return unpadded, nil
}

func deriveKey(kdf algorithmIdentifier, passphrase []byte, keyLen int) ([]byte, error) {
	switch {
	case kdf.Algorithm.Equal(oidScrypt):
		var p scryptParams
		if rest, err := asn1.Unmarshal(kdf.Parameters.FullBytes, &p); err != nil || len(rest) > 0 {
			return nil, errors.New("malformed scrypt parameters")
		}
		if p.KeyLength != 0 && p.KeyLength != keyLen {
			return nil, errors.New("scrypt key length does not fit the cipher")
		}
		if p.N < 2 || p.N > maxScryptN || p.R < 1 || p.R > maxScryptR || p.P < 1 || p.P > maxScryptP ||
			128*p.N*p.R > maxScryptMemory || 128*p.N*p.R*p.P > maxScryptWork {
			return nil, fmt.Errorf("scrypt parameters out of range (N=%d r=%d p=%d)", p.N, p.R, p.P)
		}
		return scrypt.Key(passphrase, p.Salt, p.N, p.R, p.P, keyLen)
	case kdf.Algorithm.Equal(oidPBKDF2):
		var p pbkdf2Params
		if rest, err := asn1.Unmarshal(kdf.Parameters.FullBytes, &p); err != nil || len(rest) > 0 {
			return nil, errors.New("malformed PBKDF2 parameters")
		}
		if p.KeyLength != 0 && p.KeyLength != keyLen {
			return nil, errors.New("PBKDF2 key length does not fit the cipher")
		}
		if p.Iterations < 1 || p.Iterations > maxPBKDF2Iterations {
			return nil, fmt.Errorf("PBKDF2 iteration count %d out of range", p.Iterations)
		}
		var h func() hash.Hash
		switch {
		case p.PRF.Algorithm == nil || p.PRF.Algorithm.Equal(oidHMACWithSHA1):
			h = sha1.New
		case p.PRF.Algorithm.Equal(oidHMACWithSHA256):
			h = sha256.New
		default:
			return nil, fmt.Errorf("unsupported PBKDF2 function %v", p.PRF.Algorithm)
		}
		return pbkdf2.Key(h, string(passphrase), p.Salt, p.Iterations, keyLen)
	default:
		return nil, fmt.Errorf("unsupported key derivation %v: use scrypt or PBKDF2", kdf.Algorithm)
	}
}

// pad adds PKCS#7 padding.
func pad(data []byte) []byte {
	n := aes.BlockSize - len(data)%aes.BlockSize
	return append(bytes.Clone(data), bytes.Repeat([]byte{byte(n)}, n)...)
}

// unpad removes PKCS#7 padding, checking all of it.
func unpad(data []byte) ([]byte, bool) {
	n := int(data[len(data)-1])
	if n == 0 || n > aes.BlockSize || n > len(data) {
		return nil, false
	}
	ok := hmac.Equal(data[len(data)-n:], bytes.Repeat([]byte{byte(n)}, n))
	return data[:len(data)-n], ok
}
