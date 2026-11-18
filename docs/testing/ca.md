# CA creation and hierarchy

## Scope

Creating the CA with `bxp init`, with its own root or under a company's
root (`--external-root`); the hierarchy of exactly one root, one
intermediate and the two SSH CA keys; the CA lifetimes; name constraints;
the root fingerprint; and replacing the intermediate with
`bxp new-intermediate`, with the offline root key or through a CSR to the
company's CA.

## Risks

- A CA that issues for names outside its name constraints.
- An intermediate that outlives the root, or a certificate that outlives
  the intermediate.
- `init` overwriting an existing CA or root key.
- CA files readable by other users.
- After a new intermediate: older certificates that no longer verify, or
  can no longer be renewed.
- A fingerprint that does not identify the root clients must trust.

## Approach

- **Unit:** creating and loading the CA, file permissions, refusing to
  overwrite, the lifetime limits, what name constraints permit and how
  they are written into the intermediate, the CSR and import under an
  external root (with [`catest`](../../internal/ca/catest) as the company
  CA), fingerprints, and loading the replaced intermediates.
- **Integration:** name constraints enforced through the server, and the
  `new-intermediate` command with its refusals.
- **E2E:** `TestNewIntermediate` moves the root key offline, replaces the
  intermediate, restarts, and checks with openssl that new and old
  certificates verify and that renewing an old one moves it over.
  `TestExternalRoot` has openssl play a two-level company PKI and checks
  that the chain delivered with a certificate reaches the company root.

## Known gaps

- RSA CA keys are covered by unit tests only; the E2E tests use ECDSA.
- The intermediate's expiry warning is tested as a calculation, not by
  running a server near the end of an intermediate's life.

## Test cases

Run one case with `go test <package> -run '^Name$'`; see [Running the tests](README.md#running-the-tests).

<!-- BEGIN GENERATED CASES: go run ./test/spec -->
38 test cases: 31 unit, 5 integration, 2 e2e.

| Case | Level | Verifies | Location |
|---|---|---|---|
| `TestFingerprint` | Unit | bxp fingerprint prints only the root fingerprint on standard output, and a bxp trust hint with the server's URL when it is set. | [cmd/bxp/fingerprint_test.go](../../cmd/bxp/fingerprint_test.go) |
| `TestFingerprintNeedsNoKeys` | Unit | The root key is meant to be moved offline after "bxp init", and the other keys may not be readable. The fingerprint needs none of them. | [cmd/bxp/fingerprint_test.go](../../cmd/bxp/fingerprint_test.go) |
| `TestFingerprintWithoutACA` | Unit | bxp fingerprint without a CA says the root certificate is missing. | [cmd/bxp/fingerprint_test.go](../../cmd/bxp/fingerprint_test.go) |
| `TestInitExternalNamesEveryFile` | Unit | bxp init under another root lists every file, the CSR once. | [cmd/bxp/init_output_test.go](../../cmd/bxp/init_output_test.go) |
| `TestInitNamesEveryFile` | Unit | bxp init lists every file it wrote: what to hand out, what to move offline, and what the server needs, with the root key's own place when it is elsewhere. | [cmd/bxp/init_output_test.go](../../cmd/bxp/init_output_test.go) |
| `TestNewIntermediateWithEncryptedKeys` | Unit | With encrypted server keys, the new intermediate key is encrypted with the same passphrase. | [cmd/bxp/intermediate_test.go](../../cmd/bxp/intermediate_test.go) |
| `TestDoctorLifetimes` | Unit | doctor says when the configuration's lifetimes differ from the certificates', and that they apply only when a certificate is made. | [cmd/bxp/lifetime_test.go](../../cmd/bxp/lifetime_test.go) |
| `TestExpiryWarning` | Unit | How early the CA warns that a CA certificate will expire: a fifth of its lifetime, at most a year. | [cmd/bxp/lifetime_test.go](../../cmd/bxp/lifetime_test.go) |
| `TestIntermediateValidityRefusedUnderExternalRoot` | Unit | Under an external root, the root's CA decides the intermediate's lifetime: a setting for it would do nothing, so it is refused. | [cmd/bxp/lifetime_test.go](../../cmd/bxp/lifetime_test.go) |
| `TestInitAndLoad` | Unit | A CA made with ECDSA or RSA keys loads again: a root and an intermediate, both CA certificates, the intermediate chaining to the root with path length 0. (1 sub-case) | [internal/ca/ca_test.go](../../internal/ca/ca_test.go) |
| `TestInitFilePermissions` | Unit | Every private key file of a new CA has mode 600. | [internal/ca/ca_test.go](../../internal/ca/ca_test.go) |
| `TestInitRefusesToOverwrite` | Unit | Creating a CA where one exists is refused, and the existing root is unchanged. | [internal/ca/ca_test.go](../../internal/ca/ca_test.go) |
| `TestInitWritesSSHPublicKeys` | Unit | A new CA writes the SSH user and host CA public keys as public key lines, matching the loaded keys, and the two keys differ. | [internal/ca/ca_test.go](../../internal/ca/ca_test.go) |
| `TestLoadRejectsMismatchedKey` | Unit | Loading a CA whose intermediate key belongs to another CA fails. | [internal/ca/ca_test.go](../../internal/ca/ca_test.go) |
| `TestLoadWithoutRootKey` | Unit | The CA loads and works with the root key offline. | [internal/ca/ca_test.go](../../internal/ca/ca_test.go) |
| `TestIssueWithinNameConstraints` | Unit | With name constraints, names inside them are issued and accepted by a client that has only the root; another domain, a look-alike, one bad name among good ones, and an email address are refused. (1 sub-case) | [internal/ca/constraints_test.go](../../internal/ca/constraints_test.go) |
| `TestNameConstraintsDNSOnlyForbidsIPs` | Unit | With DNS domains only, no IP address is allowed: not every one. | [internal/ca/constraints_test.go](../../internal/ca/constraints_test.go) |
| `TestNameConstraintsInTheIntermediate` | Unit | Name constraints go into the intermediate, critical: the allowed DNS domains and IP ranges, and no email addresses when none are listed; the root has none. | [internal/ca/constraints_test.go](../../internal/ca/constraints_test.go) |
| `TestPermits` | Unit | Which names the constraints permit: a domain and its subdomains, or only subdomains with a leading dot, for DNS names and email addresses; no constraints allow everything. | [internal/ca/constraints_test.go](../../internal/ca/constraints_test.go) |
| `TestImportRefusals` | Unit | Importing an intermediate is refused when it is not a CA, cannot sign CRLs, chains to another root, lacks its chain or root, or is for another key; after a refusal the CA still waits. (1 sub-case) | [internal/ca/external_test.go](../../internal/ca/external_test.go) |
| `TestIntermediateCSR` | Unit | The CSR asks for what an intermediate needs. | [internal/ca/external_test.go](../../internal/ca/external_test.go) |
| `TestReplaceUnderAnotherRoot` | Unit | Replacing the intermediate under another root: a new CSR, then its certificate. The root cannot change. | [internal/ca/external_test.go](../../internal/ca/external_test.go) |
| `TestUnderAnotherRoot` | Unit | A CA under a company root: waits for its intermediate, imports the signed chain in any order with extra certificates, has the company's root; its certificates are accepted by a machine that trusts only the company root, and its CRL is signed by its intermediate. | [internal/ca/external_test.go](../../internal/ca/external_test.go) |
| `TestCertFingerprint` | Unit | Certificate fingerprints are 64 lower-case hex digits, different for different certificates. | [internal/ca/fingerprint_test.go](../../internal/ca/fingerprint_test.go) |
| `TestSSHFingerprint` | Unit | SSH key fingerprints are SHA256:, the same for the same key whatever its comment, and different for different keys. | [internal/ca/fingerprint_test.go](../../internal/ca/fingerprint_test.go) |
| `TestX509Fingerprint` | Unit | Public key fingerprints are SHA256:, the same for the same key, different for different keys; something that is not a key is an error. | [internal/ca/fingerprint_test.go](../../internal/ca/fingerprint_test.go) |
| `TestBuiltInLifetimes` | Unit | The built-in profiles are short-lived; custom profiles are for anything longer. | [internal/ca/lifetime_test.go](../../internal/ca/lifetime_test.go) |
| `TestConfiguredLifetimes` | Unit | Configured root and intermediate lifetimes are used; an intermediate that would outlive the root is refused at init. | [internal/ca/lifetime_test.go](../../internal/ca/lifetime_test.go) |
| `TestDefaultLifetimes` | Unit | By default the root lives 10 years and the intermediate 3. | [internal/ca/lifetime_test.go](../../internal/ca/lifetime_test.go) |
| `TestReplacementMayNotOutliveTheRoot` | Unit | A replacement intermediate that would outlive the root is refused, not shortened, and nothing changes; with a shorter lifetime it is made. | [internal/ca/lifetime_test.go](../../internal/ca/lifetime_test.go) |
| `TestReplacedIntermediatesAreLoaded` | Unit | After a new intermediate, Load knows the replaced one, so that the certificates it issued can still be renewed. | [internal/ca/replace_test.go](../../internal/ca/replace_test.go) |
| `TestNameConstraints` | Integration | With name constraints, names inside them are issued and names outside are refused even when the token allows them; bxp doctor shows the constraints and warns when the configuration changed; a new intermediate takes the configured ones. | [cmd/bxp/constraints_test.go](../../cmd/bxp/constraints_test.go) |
| `TestExternalRoot` | Integration | The whole road under a company root: init makes a CSR, the company's CA signs it, the import puts it in place, and certificates from BastionXP CA are trusted by machines that only know the company root. | [cmd/bxp/external_test.go](../../cmd/bxp/external_test.go) |
| `TestNewIntermediate` | Integration | bxp new-intermediate: refused without --yes while certificates are valid, and asks; a no changes nothing; after a yes the old key is gone and only the old certificate kept; after a restart the new intermediate signs, chains to the same root and is served, old certificates still verify, and the next change warns only about what the new one issued. | [cmd/bxp/intermediate_test.go](../../cmd/bxp/intermediate_test.go) |
| `TestNewIntermediateRefusals` | Integration | bxp new-intermediate refuses a wrong root passphrase and another root key, and changes nothing in the data directory. | [cmd/bxp/intermediate_test.go](../../cmd/bxp/intermediate_test.go) |
| `TestNewIntermediateWithoutCertificates` | Integration | Nothing valid from the current intermediate: no question. | [cmd/bxp/intermediate_test.go](../../cmd/bxp/intermediate_test.go) |
| `TestExternalRoot` | E2E | A CA under a company's root, two levels up, played by openssl: a root and an issuing CA. The CSR from "bxp init --external-root" is signed by the issuing CA; after the import the CA issues certificates that verify against the company root, from what clients are sent. | [test/e2e/maintenance_test.go](../../test/e2e/maintenance_test.go) |
| `TestNewIntermediate` | E2E | A new intermediate, made with the root key from offline storage: after a restart new certificates come from it, old ones still verify, and renewing an old one moves it over. | [test/e2e/maintenance_test.go](../../test/e2e/maintenance_test.go) |
<!-- END GENERATED CASES -->
