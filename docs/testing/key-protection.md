# Key protection

## Scope

The root key, always encrypted, with its passphrase asked at `init`; the
server's keys, optionally encrypted, with the passphrase from
`ca.key_passphrase_file`, a systemd credential, `BXP_KEY_PASSPHRASE_FILE`,
`BXP_KEY_PASSPHRASE` or the terminal; and the key file format (encrypted
PKCS#8, compatible with OpenSSL).

## Risks

- An unencrypted root key, or a weak passphrase.
- A passphrase that leaks: into logs, output, or the environment of other
  programs.
- The passphrase taken from an unexpected place, or a wrong one accepted.
- Key files that OpenSSL cannot read, or key derivation parameters chosen
  to exhaust the machine.

## Approach

- **Unit:** encrypting and reading key files, including with OpenSSL
  itself (`TestOpenSSL`, skipped when openssl is missing), refusing
  damaged files and expensive parameters; `init` encrypting the root key
  and `--root-key-out`; the order of the passphrase sources and their
  refusals; `BXP_KEY_PASSPHRASE` removed from the environment once read;
  the passphrase prompts (length checked before the second question,
  three tries); the startup log line about which keys are encrypted.
- **Fuzz:** `FuzzParse`, any key file.
- **Integration:** the server starting with encrypted keys.
- **E2E:** `TestEncryptedServerKeys` starts the real server with each
  passphrase source, and checks that a wrong or missing one stops it at
  once with a message that names its source, and that the passphrase is
  never printed. `TestNoSecretsInLogs` (Operations) checks the logs.

## Known gaps

- A credential sealed to a TPM (`systemd-creds`) is not tested; the tests
  give the server a credential directory as systemd would.

## Test cases

Run one case with `go test <package> -run '^Name$'`; see [Running the tests](README.md#running-the-tests).

<!-- BEGIN GENERATED CASES: go run ./test/spec -->
22 test cases: 19 unit, 1 fuzz, 1 integration, 1 e2e.

| Case | Level | Verifies | Location |
|---|---|---|---|
| `TestInitEncryptsTheRootKey` | Unit | bxp init encrypts the root key; without a key passphrase, the server's keys stay plain. | [cmd/bxp/keys_test.go](../../cmd/bxp/keys_test.go) |
| `TestInitRefusals` | Unit | bxp init refuses to run without a root passphrase or with the same passphrase for the root and the server's keys, and creates nothing; a short passphrase is refused. (1 sub-case) | [cmd/bxp/keys_test.go](../../cmd/bxp/keys_test.go) |
| `TestInitRootKeyOut` | Unit | bxp init with --root-key-out writes the root key there, encrypted, and not into the data directory. | [cmd/bxp/keys_test.go](../../cmd/bxp/keys_test.go) |
| `TestKeyPassphraseLeavesTheEnvironment` | Unit | The passphrase itself does not stay in the environment, where programs BastionXP CA starts would inherit it. | [cmd/bxp/keys_test.go](../../cmd/bxp/keys_test.go) |
| `TestLogKeyProtection` | Unit | The startup log says which keys are encrypted. The passphrase "bxp init" asks for is the root key's, so the log says so when the server's keys are not encrypted. (3 sub-cases) | [cmd/bxp/keys_test.go](../../cmd/bxp/keys_test.go) |
| `TestServerKeyPassphraseRefusals` | Unit | The server's key passphrase is refused when none is given for encrypted keys, when it is wrong, and when the keys are not encrypted. (1 sub-case) | [cmd/bxp/keys_test.go](../../cmd/bxp/keys_test.go) |
| `TestServerKeyPassphraseSources` | Unit | Every place the server's passphrase can come from. (1 sub-case) | [cmd/bxp/keys_test.go](../../cmd/bxp/keys_test.go) |
| `TestAskNewPassphrase` | Unit | Asking for a new passphrase: the rule is shown first; a short one is refused before it is asked again; two that differ are asked again; after three failed tries it gives up. (1 sub-case) | [cmd/bxp/passphrase_test.go](../../cmd/bxp/passphrase_test.go) |
| `TestInitFailsBeforeAsking` | Unit | "bxp init" on a data directory that already holds a CA, or with a root key already where it would write one, fails before asking for any passphrase. Tests have no terminal, so asking would fail differently. (1 sub-case) | [cmd/bxp/passphrase_test.go](../../cmd/bxp/passphrase_test.go) |
| `TestInitKeepsAnExistingRootKey` | Unit | An existing root key is never overwritten, and a refused Init leaves nothing behind. | [internal/ca/encrypted_test.go](../../internal/ca/encrypted_test.go) |
| `TestInitWithEncryptedKeys` | Unit | With passphrases, the root key goes only to its offline place, encrypted with the root passphrase; the server's keys are encrypted with their own passphrase, and the CA loads only with that one. | [internal/ca/encrypted_test.go](../../internal/ca/encrypted_test.go) |
| `TestRefusesExpensiveCombination` | Unit | A file that asks for 4 GiB of scrypt memory with parameters that are each within their own limit. | [internal/keyfile/fuzz_test.go](../../internal/keyfile/fuzz_test.go) |
| `TestEncryptedNeedsTheRightPassphrase` | Unit | An encrypted key needs a passphrase and the exact one; encrypting the same key twice gives different files (random salt and IV). | [internal/keyfile/keyfile_test.go](../../internal/keyfile/keyfile_test.go) |
| `TestGarbage` | Unit | Empty files, text, damaged encrypted keys and other things that are not a key are errors. | [internal/keyfile/keyfile_test.go](../../internal/keyfile/keyfile_test.go) |
| `TestIsEncrypted` | Unit | Whether a key file is encrypted is told without the passphrase. | [internal/keyfile/keyfile_test.go](../../internal/keyfile/keyfile_test.go) |
| `TestOpenSSL` | Unit | OpenSSL reads our files, and we read OpenSSL's: the format is the standard one, so administrators can use their usual tools. (1 sub-case) | [internal/keyfile/keyfile_test.go](../../internal/keyfile/keyfile_test.go) |
| `TestPlainKeyIgnoresThePassphrase` | Unit | A plain key reads with or without a passphrase. | [internal/keyfile/keyfile_test.go](../../internal/keyfile/keyfile_test.go) |
| `TestRefusesExpensiveParameters` | Unit | A crafted file must not make us spend gigabytes of memory. | [internal/keyfile/keyfile_test.go](../../internal/keyfile/keyfile_test.go) |
| `TestRoundTrip` | Unit | Every key type is written and read back as the same key, plain or encrypted with a passphrase, under the right PEM type. (1 sub-case) | [internal/keyfile/keyfile_test.go](../../internal/keyfile/keyfile_test.go) |
| `FuzzParse` | Fuzz | Feeds arbitrary key files to Parse. It must never panic, and what it accepts must be a usable key. | [internal/keyfile/fuzz_test.go](../../internal/keyfile/fuzz_test.go) |
| `TestServeWithEncryptedKeys` | Integration | The whole road with encrypted keys: serve, a token on the CA machine, a certificate. | [cmd/bxp/keys_test.go](../../cmd/bxp/keys_test.go) |
| `TestEncryptedServerKeys` | E2E | The server's keys encrypted (init with a configured passphrase): the server starts with the passphrase from each place it looks, and stops with a clear error, at once, without it or with a wrong one. There is no terminal to ask on. (4 sub-cases) | [test/e2e/keys_test.go](../../test/e2e/keys_test.go) |
<!-- END GENERATED CASES -->
