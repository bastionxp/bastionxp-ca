# SCEP

## Scope

The SCEP server (RFC 8894): GetCACert, GetCACaps, PKIOperation for
enrollment and renewal, and GetCert; enrollment with a one-time token as
the challenge, or with the shared challenge (`scep.static`) and its
domains and hourly limit; the SCEP server's own certificate (RA); and
`bxp scep`.

## Risks

- Enrollment without a valid challenge, or a shared challenge used for
  names outside its domains or beyond its limit.
- A refused request that uses the token up.
- Weak keys, or keys a device cannot use, accepted.
- Malformed messages that crash the server.
- Renewing a certificate over SCEP that was not obtained over SCEP.

## Approach

- **Unit:** the challenge in the request, and the client's checks before it
  asks the CA.
- **Fuzz:** `FuzzPKIOperation` and `FuzzChallenge`; `TestMutatedMessages`
  sends 2,000 damaged messages on every run.
- **Integration:** the SCEP server and client together: enrollment with a
  token (held to its names, and not spent by a refusal), the shared
  challenge and its limits, weak keys and an ECDSA device refused,
  renewal, GetCert, unknown operations, and the RA certificate's renewal.
- **E2E:** `TestSCEPClients` enrolls with `bxp scep` and micromdm's
  `scepclient`; `TestSCEPStaticChallenge` and `TestSCEPStaticLimit` test
  the shared challenge with `scepclient`, checking the reason in the
  server's log; `TestSCEPGetCert` fetches a certificate again.

## Known gaps

- Device management systems (Intune, Jamf) and real devices are not
  tested. `scepclient` reaches the CA through a plain HTTP proxy in the
  test, because it cannot be told which root to trust.

## Test cases

Run one case with `go test <package> -run '^Name$'`; see [Running the tests](README.md#running-the-tests).

<!-- BEGIN GENERATED CASES: go run ./test/spec -->
40 test cases: 2 unit, 2 fuzz, 32 integration, 4 e2e.

| Case | Level | Verifies | Location |
|---|---|---|---|
| `TestSCEPChecksBeforeAskingTheCA` | Unit | bxp scep enroll fails before asking the CA with no names, an existing key file without --force, and no CA URL. | [cmd/bxp/scep_test.go](../../cmd/bxp/scep_test.go) |
| `TestChallengeInCSR` | Unit | The challenge password in a CSR is written and read back, short or long, and the CSR stays valid for other software; an empty challenge is an error; a CSR without one, or something that is not a CSR, has none. | [internal/scep/scep_test.go](../../internal/scep/scep_test.go) |
| `FuzzChallenge` | Fuzz | Reads the challenge password out of arbitrary CSRs. | [internal/scep/fuzz_test.go](../../internal/scep/fuzz_test.go) |
| `FuzzPKIOperation` | Fuzz | Sends arbitrary messages to the SCEP endpoint. The server must never panic, and never answer with a server error: a message it cannot read is the sender's fault. | [internal/scep/fuzz_test.go](../../internal/scep/fuzz_test.go) |
| `TestRenewOnlyTheWayItWasObtained` | Integration | Each certificate is renewed the way it was obtained: bxp renew only for certificates from the API, SCEP renewal only for SCEP ones. | [cmd/bxp/scep_renew_test.go](../../cmd/bxp/scep_renew_test.go) |
| `TestSCEPGetCert` | Integration | bxp scep getcert fetches an enrolled certificate again by serial number: the same file as at enrollment; an existing file needs --force; another device's key, an unknown serial number, and one that is not hex are refused. | [cmd/bxp/scep_renew_test.go](../../cmd/bxp/scep_renew_test.go) |
| `TestSCEPRenew` | Integration | bxp scep renew, with the certificate as the proof: not before it is due unless forced; a new certificate and RSA key of the same size, the same names and usages, with the intermediate in the file; a revoked certificate is refused and the files stay. | [cmd/bxp/scep_renew_test.go](../../cmd/bxp/scep_renew_test.go) |
| `TestSCEP` | Integration | The whole road with SCEP: a token as the challenge, a certificate back. | [cmd/bxp/scep_test.go](../../cmd/bxp/scep_test.go) |
| `TestSCEPNeedsAReadableRootFile` | Integration | A root file that cannot be read is an error, and the token is not sent. (That an RA of another CA is refused is tested in the scep package.) | [cmd/bxp/scep_test.go](../../cmd/bxp/scep_test.go) |
| `TestSCEPRefusedForNamesNotInTheToken` | Integration | bxp scep enroll for a name not in the token is refused, and writes no files. | [cmd/bxp/scep_test.go](../../cmd/bxp/scep_test.go) |
| `TestSCEPStaticPasswordLength` | Integration | The static challenge password must be long enough: the server does not start with a short one. | [cmd/bxp/scep_test.go](../../cmd/bxp/scep_test.go) |
| `TestSCEPWhenTheCAHasNoSCEP` | Integration | bxp scep enroll against a CA without SCEP says the server is not there, and the token still works for a normal request. | [cmd/bxp/scep_test.go](../../cmd/bxp/scep_test.go) |
| `TestSCEPWithBrowserLogin` | Integration | Without --token, an admin logs in with the browser, as with the other client commands. | [cmd/bxp/scep_test.go](../../cmd/bxp/scep_test.go) |
| `TestMutatedMessages` | Integration | Messages with a few random bytes changed: the server answers each fast, and never with a server error. (Go's fuzzing engine is slow on this target, so this runs a plain loop as well, on every test run.) | [internal/scep/fuzz_test.go](../../internal/scep/fuzz_test.go) |
| `TestClientChecksTheAnswer` | Integration | A client must not accept an answer that is not from the RA, or that belongs to another request. | [internal/scep/scep_test.go](../../internal/scep/scep_test.go) |
| `TestDeviceWithECDSAKeyIsRefused` | Integration | A device with an ECDSA key cannot use SCEP: the answer could not be encrypted for it. It must get a refusal, not a server error. | [internal/scep/scep_test.go](../../internal/scep/scep_test.go) |
| `TestEnroll` | Integration | The whole road: a device asks for the server's certificates, sends a CSR with the challenge, and gets its certificate. | [internal/scep/scep_test.go](../../internal/scep/scep_test.go) |
| `TestEnrollIsRefused` | Integration | SCEP enrollment is refused with a wrong challenge, without a challenge, with a CSR for another key than the one that signs the message, and with something that is not a CSR; nothing is issued. | [internal/scep/scep_test.go](../../internal/scep/scep_test.go) |
| `TestGetCACapsAndUnknownOperations` | Integration | GetCACaps lists POSTPKIOperation, SHA-256, AES and SCEPStandard, and Renewal only when the server can renew; unknown operations are refused with 400. | [internal/scep/scep_test.go](../../internal/scep/scep_test.go) |
| `TestGetCert` | Integration | GetCert: the holder of a certificate's key gets it again; nobody else. | [internal/scep/scep_test.go](../../internal/scep/scep_test.go) |
| `TestLoadOrCreateRA` | Integration | The SCEP RA certificate: an RSA key, not a CA, for signing and key encipherment, key file mode 600; created once and reused; a key that does not match the certificate is an error. | [internal/scep/scep_test.go](../../internal/scep/scep_test.go) |
| `TestMessagesTheServerCannotOpen` | Integration | SCEP messages encrypted for another key, changed after signing, or without SCEP attributes are refused with 400, and issue nothing. (1 sub-case) | [internal/scep/scep_test.go](../../internal/scep/scep_test.go) |
| `TestOtherMessageTypesAreRefused` | Integration | Enrollment, renewal and GetCert are supported. Other message types, and renewal or GetCert messages that are not what they say, get a proper SCEP refusal, and no certificate. | [internal/scep/scep_test.go](../../internal/scep/scep_test.go) |
| `TestPKIOperationWithGET` | Integration | Old devices send the message as a parameter of a GET request. | [internal/scep/scep_test.go](../../internal/scep/scep_test.go) |
| `TestRAIsRenewedBeforeItEnds` | Integration | An RA certificate that ends soon is replaced at the next start. | [internal/scep/scep_test.go](../../internal/scep/scep_test.go) |
| `TestRenew` | Integration | Renewal: signed with the current certificate, a CSR for a new key. | [internal/scep/scep_test.go](../../internal/scep/scep_test.go) |
| `TestVerifyRAAgainstAnotherCA` | Integration | The RA of one CA must not pass as the RA of another. | [internal/scep/scep_test.go](../../internal/scep/scep_test.go) |
| `TestSCEPStaticAndTokens` | Integration | Tokens keep working next to the password; anything else is refused. | [internal/server/scep_static_test.go](../../internal/server/scep_static_test.go) |
| `TestSCEPStaticChallenge` | Integration | SCEP with a static password, for device management systems: a device known only by its serial number gets a client certificate; names in the allowed domains are issued; DNS names elsewhere, look-alike domains, wildcards, IP addresses and email addresses outside the allowed domains are refused. (1 sub-case) | [internal/server/scep_static_test.go](../../internal/server/scep_static_test.go) |
| `TestSCEPStaticLimit` | Integration | Enrollments with the static password are limited per hour; tokens are not counted against that limit. | [internal/server/scep_static_test.go](../../internal/server/scep_static_test.go) |
| `TestSCEPStaticServerTemplate` | Integration | The static password can issue with another profile, here TLS server certificates. | [internal/server/scep_static_test.go](../../internal/server/scep_static_test.go) |
| `TestSCEPEnrollIsHeldToTheToken` | Integration | The rules for tokens hold for SCEP as they do for the API. (1 sub-case) | [internal/server/scep_test.go](../../internal/server/scep_test.go) |
| `TestSCEPEnrollWithToken` | Integration | The whole road: an administrator makes a token, the device sends it as its SCEP challenge and gets a certificate. | [internal/server/scep_test.go](../../internal/server/scep_test.go) |
| `TestSCEPIsOffUnlessConfigured` | Integration | The SCEP endpoint is not found unless SCEP is configured. | [internal/server/scep_test.go](../../internal/server/scep_test.go) |
| `TestSCEPRefusalDoesNotSpendTheToken` | Integration | A request refused for its names does not use up the token, as with the API. | [internal/server/scep_test.go](../../internal/server/scep_test.go) |
| `TestSCEPRefusesWeakKeys` | Integration | A device's key must be strong enough, as for every other certificate. | [internal/server/scep_test.go](../../internal/server/scep_test.go) |
| `TestSCEPGetCert` | E2E | "bxp scep getcert" fetches a certificate again, by serial number, with its key: exactly the one issued. | [test/e2e/scep_static_test.go](../../test/e2e/scep_static_test.go) |
| `TestSCEPStaticChallenge` | E2E | The shared challenge, as device management systems use it: devices in the allowed domain enroll; another domain, or a wrong challenge, do not. | [test/e2e/scep_static_test.go](../../test/e2e/scep_static_test.go) |
| `TestSCEPStaticLimit` | E2E | scep.static.max_per_hour stops enrollments with the shared challenge. | [test/e2e/scep_static_test.go](../../test/e2e/scep_static_test.go) |
| `TestSCEPClients` | E2E | Devices enroll over SCEP with a one-time token as the challenge, with bxp's own client and with micromdm's scepclient. (2 sub-cases) | [test/e2e/scep_test.go](../../test/e2e/scep_test.go) |
<!-- END GENERATED CASES -->
