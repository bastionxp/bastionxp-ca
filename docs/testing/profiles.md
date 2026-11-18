# Certificate profiles

## Scope

The built-in profiles and their lifetimes, profiles of your own (X.509
and SSH) in the configuration, and the profiles each verifier uses
(`cert_profile`).

## Risks

- A certificate with the wrong key usages or extended key usages.
- A lifetime beyond the profile's maximum.
- A profile of your own that the configuration accepts but cannot work.
- SSH extensions or options leaking from one profile to another.

## Approach

- **Unit:** validating profiles in the configuration and their refusals,
  what a profile puts into a certificate, SSH profiles, and the verifiers'
  `cert_profile`.
- **Integration:** `TestProfileEndToEnd`, a profile of your own requested
  through the server.
- **E2E:** indirectly: `tls-device` certificates over SCEP and
  `tls-client` certificates for mutual TLS are checked by openssl and Go
  in the SCEP and TLS chapters.

## Known gaps

- Profiles of your own are not tested end to end with the real binary.
- Email and code-signing certificates are not checked with outside
  software (mail clients, code-signing tools).

## Test cases

Run one case with `go test <package> -run '^Name$'`; see [Running the tests](README.md#running-the-tests).

<!-- BEGIN GENERATED CASES: go run ./test/spec -->
7 test cases: 6 unit, 1 integration.

| Case | Level | Verifies | Location |
|---|---|---|---|
| `TestProfileInTheCertificate` | Unit | A custom profile's organizational unit, policies, custom extension, key usage and extended key usage are in the certificate. | [internal/ca/profiles_test.go](../../internal/ca/profiles_test.go) |
| `TestProfileRules` | Unit | A custom profile's rules refuse names it does not allow (DNS names, IP addresses, wildcards), small RSA keys and other curves, a missing common name, and host names on code signing; the built-in profiles are unaffected, and an unknown profile is not found. (1 sub-case) | [internal/ca/profiles_test.go](../../internal/ca/profiles_test.go) |
| `TestProfile` | Unit | Custom X.509 profiles are read with their lifetime, subject rules, names, policies, extensions and key rules, and can be based on email for S/MIME; the built-in profiles remain. | [internal/config/profiles_test.go](../../internal/config/profiles_test.go) |
| `TestProfileRefusals` | Unit | Invalid X.509 profiles are refused, each with its message: bad or taken names, an unknown base, bad lifetimes, unknown key usages, extensions the CA sets itself or that are not one DER value in hex, bad policy OIDs, wildcards or email without a host name where not allowed, and bad key rules; a name used twice. | [internal/config/profiles_test.go](../../internal/config/profiles_test.go) |
| `TestSSHProfiles` | Unit | Custom SSH profiles are read with their lifetime, extensions (an empty list meaning none) and critical options, for users and hosts; unknown extensions or options, a bad source-address, options on a host profile, X.509 settings on SSH and the reverse, and the ssh- name prefix are refused. | [internal/config/profiles_test.go](../../internal/config/profiles_test.go) |
| `TestVerifierCertProfiles` | Unit | Each verifier's cert_profile must be of the right kind. | [internal/config/profiles_test.go](../../internal/config/profiles_test.go) |
| `TestProfileEndToEnd` | Integration | A profile of the administrator's own, used like a built-in template. | [cmd/bxp/profiles_test.go](../../cmd/bxp/profiles_test.go) |
<!-- END GENERATED CASES -->
