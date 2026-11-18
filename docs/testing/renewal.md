# Renewal

## Scope

`bxp renew` for TLS certificates and SSH host certificates, with a proof
signed by the current certificate's key; when renewal is due (a third of
the lifetime left); the new files (a new TLS key, the same SSH host key);
and `--exec`. ACME and SCEP renewal are in their own chapters.

## Risks

- Renewing a revoked, expired, or foreign certificate, or a user SSH
  certificate.
- A proof used twice.
- Renewing a certificate that was obtained another way (ACME, SCEP).
- New files with other permissions or owner than the old ones, or a file
  replaced while a program reads it.

## Approach

- **Unit:** when renewal is due, and the renewed lifetime.
- **Fuzz:** `FuzzRenew`, any renewal request.
- **Integration:** the renewal endpoints with every refusal, one use per
  proof, renewal only the way a certificate was obtained, and the client:
  not yet, keeping permissions, not disturbing an open file.
- **E2E:** `TestRenew`: nothing to do while fresh, `--force`, `--exec`,
  and refused once revoked. `TestSSHHostRenew` keeps the host key. Renewal
  onto a new intermediate is in the CA chapter.

## Known gaps

- Renewal run as root for files owned by another user is not tested.

## Test cases

Run one case with `go test <package> -run '^Name$'`; see [Running the tests](README.md#running-the-tests).

<!-- BEGIN GENERATED CASES: go run ./test/spec -->
22 test cases: 2 unit, 1 fuzz, 17 integration, 2 e2e.

| Case | Level | Verifies | Location |
|---|---|---|---|
| `TestRenewDue` | Unit | A certificate is due for renewal when a third of its lifetime or less is left. | [cmd/bxp/renew_test.go](../../cmd/bxp/renew_test.go) |
| `TestRenewedValidity` | Unit | A renewed certificate keeps the old one's lifetime, and gets the profile's default when the old lifetime is above the maximum or too short to be real. | [internal/server/renew_test.go](../../internal/server/renew_test.go) |
| `FuzzRenew` | Fuzz | Sends arbitrary renewal proofs and bodies. The answer is never a server error, and a certificate is issued only for a proof really signed with a certificate's key, which only the seed is. | [internal/server/fuzz_test.go](../../internal/server/fuzz_test.go) |
| `TestRenewDoesNotDisturbAnOpenFile` | Integration | A program that has the old files open keeps reading the old content: the new files are new files, the old ones stay until it closes them. | [cmd/bxp/renew_test.go](../../cmd/bxp/renew_test.go) |
| `TestRenewKeepsFilePermissions` | Integration | The program that uses the certificate may read the key through its group. A renewal must not lock it out by tightening the permissions, nor open them up. | [cmd/bxp/renew_test.go](../../cmd/bxp/renew_test.go) |
| `TestRenewNotYet` | Integration | A fresh certificate is left alone: a daily timer does nothing for the first two thirds of its life. | [cmd/bxp/renew_test.go](../../cmd/bxp/renew_test.go) |
| `TestRenewRefusedAfterRevocation` | Integration | bxp renew of a revoked certificate fails, says so, and leaves the files as they were. | [cmd/bxp/renew_test.go](../../cmd/bxp/renew_test.go) |
| `TestRenewRefusedWhenExpired` | Integration | bxp renew of an expired certificate fails and says a new token is needed. | [cmd/bxp/renew_test.go](../../cmd/bxp/renew_test.go) |
| `TestRenewRefusesBadInput` | Integration | bxp renew refuses missing files, a file that is not a certificate, an SSH key instead of a certificate, the wrong key, and an SSH user certificate. (1 sub-case) | [cmd/bxp/renew_test.go](../../cmd/bxp/renew_test.go) |
| `TestRenewSSHHost` | Integration | bxp renew of an SSH host certificate: not before a third of its lifetime is left unless forced; the same host key and principals; refused once the certificate is revoked. | [cmd/bxp/renew_test.go](../../cmd/bxp/renew_test.go) |
| `TestRenewTLS` | Integration | bxp renew of a TLS certificate: a new certificate and a new key that belong together, the same names and lifetime, the key file mode 600, no files left over, the --exec command run; the renewed certificate renews in turn. | [cmd/bxp/renew_test.go](../../cmd/bxp/renew_test.go) |
| `TestRenewSSH` | Integration | Renewing an SSH host certificate: a new serial number, the same type, key ID and principals, the same host key, signed by the host CA. | [internal/server/renew_test.go](../../internal/server/renew_test.go) |
| `TestRenewSSHRefusals` | Integration | SSH renewal refuses a user certificate, a host certificate of another CA, a proof signed with another key, a proof meant for TLS, and a revoked certificate. (1 sub-case) | [internal/server/renew_test.go](../../internal/server/renew_test.go) |
| `TestRenewSSHWithTheClient` | Integration | The client library renews an SSH host certificate through a TLS server. | [internal/server/renew_test.go](../../internal/server/renew_test.go) |
| `TestRenewX509` | Integration | Renewing a TLS certificate with a proof signed by its key: the new certificate has a new serial number and a new key, keeps the old one's names, kind and lifetime whatever names the request asks for, and is in the list of issued certificates. | [internal/server/renew_test.go](../../internal/server/renew_test.go) |
| `TestRenewX509ProofWorksOnce` | Integration | A renewal proof works only once: the same request sent again is refused as already used. | [internal/server/renew_test.go](../../internal/server/renew_test.go) |
| `TestRenewX509Refusals` | Integration | Every way a TLS renewal is refused, with its status and message: no proof or a malformed one, a proof signed with another key, a certificate of another CA or one missing from the list, a proof for another request body or for SSH, one that lives too long or has expired, the same key again, a bad CSR or an unknown field. A correct request still works afterwards. (1 sub-case) | [internal/server/renew_test.go](../../internal/server/renew_test.go) |
| `TestRenewX509RefusesExpiredCertificates` | Integration | An expired TLS certificate cannot be renewed: it needs a new token. | [internal/server/renew_test.go](../../internal/server/renew_test.go) |
| `TestRenewX509RefusesRevokedCertificates` | Integration | A revoked TLS certificate cannot be renewed. | [internal/server/renew_test.go](../../internal/server/renew_test.go) |
| `TestRenewX509WithTheClient` | Integration | The road from a client's point of view, with the client package. | [internal/server/renew_test.go](../../internal/server/renew_test.go) |
| `TestSSHHostRenew` | E2E | "bxp renew" on an SSH host certificate: a new certificate for the same host key (a host keeps its key: clients know it), and the principals and kind stay. | [test/e2e/agent_test.go](../../test/e2e/agent_test.go) |
| `TestRenew` | E2E | "bxp renew": nothing to do while the certificate is fresh, a new key and certificate with --force, the --exec command after it, and no renewal once revoked. | [test/e2e/core_test.go](../../test/e2e/core_test.go) |
<!-- END GENERATED CASES -->
