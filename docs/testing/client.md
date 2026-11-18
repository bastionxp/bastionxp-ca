# Client connection and trust

## Scope

How a client reaches the CA: `bxp trust` (the fingerprint check, saving
the address and root, `--ssh`), the HTTP API client, and the command
line's structure, errors and exit codes.

## Risks

- Trusting the wrong CA: a wrong fingerprint accepted, or a server that
  only copies the root.
- A message that hides what went wrong: an unreachable server, a server of
  another CA, a name not in the server's certificate.
- A one-time token spent by a request that failed.

## Approach

- **Unit:** fingerprints, addresses, the help's command groups.
- **Integration:** `bxp trust` and its refusals, other commands using the
  saved trust, and the API client's handling of answers and errors.
- **E2E:** `TestCommandLine`: version, an unknown command, a second
  `init`, the fingerprint against openssl's, a wrong fingerprint refused.
  `TestClientErrors`: nothing at the address, a server of another CA,
  `bxp trust` for another CA, the CA down: each with a clear message, a
  non-zero exit status, no crash, and the token not spent.

## Known gaps

- Installing the root into the system trust store is printed for the
  user to run, not done, and not tested.

## Test cases

Run one case with `go test <package> -run '^Name$'`; see [Running the tests](README.md#running-the-tests).

<!-- BEGIN GENERATED CASES: go run ./test/spec -->
23 test cases: 7 unit, 14 integration, 2 e2e.

| Case | Level | Verifies | Location |
|---|---|---|---|
| `TestClientNeedsAGoodURL` | Unit | The client commands need a CA address, and an https:// one. (1 sub-case) | [cmd/bxp/client_test.go](../../cmd/bxp/client_test.go) |
| `TestHelpGroups` | Unit | The help shows the commands for getting certificates apart from those for running the CA, each group in the order of use. | [cmd/bxp/main_test.go](../../cmd/bxp/main_test.go) |
| `TestNoGetCommand` | Unit | The old command names are gone. | [cmd/bxp/serve_test.go](../../cmd/bxp/serve_test.go) |
| `TestNormalizeFingerprint` | Unit | A fingerprint is accepted in upper case, with colons, as openssl prints it (the whole line too), with a SHA256: prefix, or with spaces around it. | [cmd/bxp/trust_test.go](../../cmd/bxp/trust_test.go) |
| `TestTrustCommandIsThere` | Unit | The trust command exists. | [cmd/bxp/trust_test.go](../../cmd/bxp/trust_test.go) |
| `TestLoginURL` | Unit | The login address is built from the CA's URL, without a double slash, and the parameters. | [internal/client/client_test.go](../../internal/client/client_test.go) |
| `TestNewRejectsBadInput` | Unit | The client refuses a missing URL, one without a scheme or over plain HTTP, a missing root file and one without a certificate. (1 sub-case) | [internal/client/client_test.go](../../internal/client/client_test.go) |
| `TestOtherCommandsUseTheSavedTrust` | Integration | After "bxp trust", the other commands need neither --ca-url nor --root. | [cmd/bxp/trust_test.go](../../cmd/bxp/trust_test.go) |
| `TestTrust` | Integration | bxp trust with the right fingerprint saves the CA's address, without a trailing slash, and its root, and shows the fingerprint; running it again for the same CA is fine. | [cmd/bxp/trust_test.go](../../cmd/bxp/trust_test.go) |
| `TestTrustDoesNotReplaceAnotherCAWithoutForce` | Integration | bxp trust for another CA needs --force to replace the saved one. | [cmd/bxp/trust_test.go](../../cmd/bxp/trust_test.go) |
| `TestTrustRefusesAServerThatOnlyCopiesTheRoot` | Integration | A server that hands out a copy of the right root, which is public, but is not itself part of that CA: someone in the middle. | [cmd/bxp/trust_test.go](../../cmd/bxp/trust_test.go) |
| `TestTrustRefusesAWrongFingerprint` | Integration | The whole point: a wrong fingerprint must stop everything. | [cmd/bxp/trust_test.go](../../cmd/bxp/trust_test.go) |
| `TestTrustRefusesBadInput` | Integration | bxp trust refuses a missing, short or non-hex fingerprint, a missing address, plain HTTP, a server that is not a BastionXP CA, and an address where nothing listens. (1 sub-case) | [cmd/bxp/trust_test.go](../../cmd/bxp/trust_test.go) |
| `TestTrustSSH` | Integration | bxp trust --ssh adds the CA's SSH host key to known_hosts as a cert- authority line, once, beside the lines already there. | [cmd/bxp/trust_test.go](../../cmd/bxp/trust_test.go) |
| `TestUseSavedTrust` | Integration | The saved CA is used when no address is given or the saved one is; another address does not get the saved root; a root given is used. | [cmd/bxp/trust_test.go](../../cmd/bxp/trust_test.go) |
| `TestClientAddressNotInTheCertificate` | Integration | The right CA, at an address its certificate is not for: said so, not as a network problem. | [internal/client/client_test.go](../../internal/client/client_test.go) |
| `TestClientDoesNotTrustAnUnknownServer` | Integration | Without the CA's root, the client refuses a server it does not trust, before its request and token reach it. | [internal/client/client_test.go](../../internal/client/client_test.go) |
| `TestLoginIsSetUp` | Integration | The client learns whether the CA has a login set up from a GET to the login endpoint, without sending any secret. | [internal/client/client_test.go](../../internal/client/client_test.go) |
| `TestServerErrorsAreReported` | Integration | The client reports the CA's error message, an error that is not from the CA by its status, a success without a certificate, and a success that is not JSON. (1 sub-case) | [internal/client/client_test.go](../../internal/client/client_test.go) |
| `TestSignSSHSendsTokenAndRequest` | Integration | The client sends an SSH request as POST to the sign endpoint, with the token as a bearer token and the request as the body, and returns the answer. | [internal/client/client_test.go](../../internal/client/client_test.go) |
| `TestSignX509SendsTokenAndRequest` | Integration | The client sends a TLS request as POST to the sign endpoint, with the token as a bearer token and the request as the body, and returns the answer. | [internal/client/client_test.go](../../internal/client/client_test.go) |
| `TestCommandLine` | E2E | The command line itself: version, unknown commands, and errors that come out before any question is asked. | [test/e2e/core_test.go](../../test/e2e/core_test.go) |
| `TestClientErrors` | E2E | Client mistakes and outages: a clear message, a non-zero exit status, no crash, and the one-time token is not spent. | [test/e2e/operations_test.go](../../test/e2e/operations_test.go) |
<!-- END GENERATED CASES -->
