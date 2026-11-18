# TLS certificates

## Scope

TLS certificates through the API (`POST /v1/x509/sign`) and `bxp tls`:
server and client certificates, names (DNS, IP, email), requested
lifetimes, the files written, and the server's own TLS certificate.

## Risks

- A certificate with wrong names, key usage or lifetime.
- Two certificates with the same serial number.
- A certificate that outlives the CA.
- Requests that should be refused accepted: wrong token, names not in
  the token, unknown profile, oversized or malformed bodies, a wrong
  authorization scheme.
- Files replaced without `--force`, or half written after a refusal.
- Certificates that real TLS software rejects.

## Approach

- **Unit:** building certificates from requests, unique serials, never
  outliving the CA, refusals, profiles by name.
- **Fuzz:** `FuzzCSR`, any certificate request.
- **Integration:** the signing endpoint with every refusal; `bxp tls`
  writing files, refusing to replace them, and writing nothing after a
  refusal; names taken from the token when `--name` is left out; the
  server's own certificate, renewed before it expires.
- **E2E:** `TestTLSHandshake`: `openssl s_server` serves a certificate
  from the real binary; `openssl s_client` and `curl` accept it for its
  name and refuse it for another; for mutual TLS, both `openssl` and Go's
  `crypto/tls` are let in with a `tls-client` certificate and refused
  without one or with a `tls-server` one.

## Known gaps

- Browsers, Java, .NET and Windows' TLS are not tested.

## Test cases

Run one case with `go test <package> -run '^Name$'`; see [Running the tests](README.md#running-the-tests).

<!-- BEGIN GENERATED CASES: go run ./test/spec -->
29 test cases: 9 unit, 1 fuzz, 18 integration, 1 e2e.

| Case | Level | Verifies | Location |
|---|---|---|---|
| `TestTLSNeedsAName` | Unit | bxp tls without --name, and a token it cannot read the names from, asks for --name. | [cmd/bxp/client_test.go](../../cmd/bxp/client_test.go) |
| `TestIssueTLSClient` | Unit | A tls-client certificate verifies for client authentication, with the common name and email address asked for and the lifetime asked for. | [internal/ca/x509_test.go](../../internal/ca/x509_test.go) |
| `TestIssueTLSServer` | Unit | A tls-server certificate verifies for its names against the root as a server certificate, is not a CA, and carries the CA's organization. | [internal/ca/x509_test.go](../../internal/ca/x509_test.go) |
| `TestIssueX509NeverOutlivesTheCA` | Unit | A certificate issued shortly before the intermediate expires ends when the intermediate does, not later. | [internal/ca/x509_test.go](../../internal/ca/x509_test.go) |
| `TestIssueX509Rejects` | Unit | Requests the profile does not allow are refused: a server certificate without a host name, a client certificate without any name, weak keys, and the other cases in the table. (1 sub-case) | [internal/ca/x509_test.go](../../internal/ca/x509_test.go) |
| `TestIssueX509SerialsAreUnique` | Unit | Two certificates never share a serial number. | [internal/ca/x509_test.go](../../internal/ca/x509_test.go) |
| `TestRequestFromCSR` | Unit | A request built from a CSR carries the CSR's names, and the certificate issued for it has them. | [internal/ca/x509_test.go](../../internal/ca/x509_test.go) |
| `TestX509TemplateByName` | Unit | The TLS profiles are found by name, and an SSH profile is not found as a TLS one. | [internal/ca/x509_test.go](../../internal/ca/x509_test.go) |
| `TestNewTLSConfigRejectsNoNames` | Unit | The server's TLS setup needs at least one name. | [internal/server/tls_test.go](../../internal/server/tls_test.go) |
| `FuzzCSR` | Fuzz | Reads arbitrary CSRs the way the sign endpoint does. Whatever is accepted must carry a valid signature: proof that the requester holds the key. | [internal/server/fuzz_test.go](../../internal/server/fuzz_test.go) |
| `TestTLS` | Integration | bxp tls writes a private key (mode 600) and a certificate for the names asked for, with the lifetime asked for, and says which files it wrote. | [cmd/bxp/client_test.go](../../cmd/bxp/client_test.go) |
| `TestTLSClientCertificate` | Integration | bxp tls with a tls-client token writes a client-authentication certificate for the email address. | [cmd/bxp/client_test.go](../../cmd/bxp/client_test.go) |
| `TestTLSDoesNotReplaceFilesWithoutForce` | Integration | bxp tls does not replace existing files unless --force is given, and refuses before asking the CA, so the token still works. | [cmd/bxp/client_test.go](../../cmd/bxp/client_test.go) |
| `TestTLSReportsRefusalAndWritesNothing` | Integration | When the CA refuses a request, bxp tls reports the CA's reason and writes no files. | [cmd/bxp/client_test.go](../../cmd/bxp/client_test.go) |
| `TestTLSNamesFromToken` | Integration | With --token and no --name, "bxp tls" asks for every name the token allows, as "bxp ssh" does with principals. | [cmd/bxp/tls_names_test.go](../../cmd/bxp/tls_names_test.go) |
| `TestSignX509` | Integration | A token and a CSR get a certificate, returned alone and as a chain with the intermediate, that verifies for each of its names (DNS and IP) against the root as a server certificate. | [internal/server/server_test.go](../../internal/server/server_test.go) |
| `TestSignX509ClientCertificate` | Integration | A tls-client token gets a certificate for client authentication only. | [internal/server/server_test.go](../../internal/server/server_test.go) |
| `TestSignX509RejectsBadRequests` | Integration | Malformed requests are refused with 400 and a message: no CSR, not PEM, a certificate instead of a CSR, a broken CSR signature, a bad, negative or too long validity, a 1024-bit RSA key, unknown fields, and a body that is not JSON. (1 sub-case) | [internal/server/server_test.go](../../internal/server/server_test.go) |
| `TestSignX509RejectsBadTokens` | Integration | A request without a token, with something that is not a token, a token signed by another key, or a damaged token is refused with 401. (1 sub-case) | [internal/server/server_test.go](../../internal/server/server_test.go) |
| `TestSignX509RejectsLargeBody` | Integration | A request body above the size limit is refused. | [internal/server/server_test.go](../../internal/server/server_test.go) |
| `TestSignX509RejectsNamesNotInToken` | Integration | A CSR with another, an extra or a wildcard name, another common name, or an extra IP address is refused with 403, and the token still works for a corrected request. (1 sub-case) | [internal/server/server_test.go](../../internal/server/server_test.go) |
| `TestSignX509RejectsTokenForUnknownTemplate` | Integration | A token for an SSH profile cannot get a TLS certificate. | [internal/server/server_test.go](../../internal/server/server_test.go) |
| `TestSignX509RejectsWrongAuthorizationScheme` | Integration | A token sent with another authorization scheme than Bearer is refused. | [internal/server/server_test.go](../../internal/server/server_test.go) |
| `TestSignX509ServerCertificateNeedsAHostName` | Integration | A server certificate needs a DNS name or IP address, not only a common name. | [internal/server/server_test.go](../../internal/server/server_test.go) |
| `TestSignX509TokenWorksOnlyOnce` | Integration | A token gets one certificate; a second request with it is refused as already used. | [internal/server/server_test.go](../../internal/server/server_test.go) |
| `TestSignX509WithRequestedValidity` | Integration | A request may ask for a lifetime within the profile's maximum, and gets it. | [internal/server/server_test.go](../../internal/server/server_test.go) |
| `TestNewTLSConfigServesACertificateFromTheCA` | Integration | The server's own TLS certificate comes from the CA and works for clients that trust only the root, by IP address and by DNS name. | [internal/server/tls_test.go](../../internal/server/tls_test.go) |
| `TestSelfCertIsRenewedBeforeItExpires` | Integration | The server's own certificate is reused while fresh and replaced once two thirds of its life have passed, before it expires. | [internal/server/tls_test.go](../../internal/server/tls_test.go) |
| `TestTLSHandshake` | E2E | TLS: a server certificate is accepted by openssl and curl for its name, and a client certificate opens a server that asks for one (mutual TLS). | [test/e2e/consumers_test.go](../../test/e2e/consumers_test.go) |
<!-- END GENERATED CASES -->
