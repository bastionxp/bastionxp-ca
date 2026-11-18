# Revocation, CRL and OCSP

## Scope

Revoking certificates (`bxp revoke`, and over ACME), recording every
certificate issued, the CRL and OCSP answers, the public HTTP address,
the cache of signed answers, and the watcher that notices revocations made
by other processes.

## Risks

- A revoked certificate reported as good, or a stale cached answer after
  a revocation.
- OCSP answers for certificates of another CA, or for serial numbers alone.
- A certificate issued but not recorded, so it cannot be revoked.
- The public address serving more than public information.

## Approach

- **Unit:** signing CRLs (with numbers that go up) and OCSP answers, every
  certificate recorded and none issued without a record, the cache and its
  limit.
- **Fuzz:** `FuzzOCSP`, any OCSP request.
- **Integration:** the public endpoints (CA certificates, CRL, OCSP over
  POST and GET, downloads), malformed and foreign requests, the public
  listener holding only public information, the watcher, and `bxp revoke`
  and `bxp list`.
- **E2E:** `TestTLSAndRevocation` revokes with the real binary, waits for
  the server to notice, and checks with `openssl ocsp` and
  `openssl crl -verify`.

## Known gaps

- SSH certificates cannot be revoked on SSH servers (there is no KRL yet);
  revoking one only stops its renewal.
- How other software acts on revocation (browsers, OpenSSL's own CRL
  checking) is not tested.

## Test cases

Run one case with `go test <package> -run '^Name$'`; see [Running the tests](README.md#running-the-tests).

<!-- BEGIN GENERATED CASES: go run ./test/spec -->
35 test cases: 11 unit, 1 fuzz, 22 integration, 1 e2e.

| Case | Level | Verifies | Location |
|---|---|---|---|
| `TestRevokeAndListNeedADatabase` | Unit | bxp revoke and bxp list certificates say there is no database for a CA that has never run. | [cmd/bxp/revoke_test.go](../../cmd/bxp/revoke_test.go) |
| `TestCRLNumbersGoUp` | Unit | Each CRL has a higher number than the one before. | [internal/ca/revocation_test.go](../../internal/ca/revocation_test.go) |
| `TestEveryCertificateIsRecorded` | Unit | Every TLS and SSH certificate the CA issues is recorded, with its profile. | [internal/ca/revocation_test.go](../../internal/ca/revocation_test.go) |
| `TestIssuedByThisCA` | Unit | An OCSP request, with SHA-1 or SHA-256, is recognised as being about this CA's certificates, and not taken by another CA. | [internal/ca/revocation_test.go](../../internal/ca/revocation_test.go) |
| `TestNoCertificateWithoutARecord` | Unit | The CA must not hand out a certificate it could not record: nobody could revoke it later. | [internal/ca/revocation_test.go](../../internal/ca/revocation_test.go) |
| `TestPublishAtWritesAddressesIntoCertificates` | Unit | With a public address set, certificates carry the CRL, OCSP and issuer- certificate addresses; without one, none. | [internal/ca/revocation_test.go](../../internal/ca/revocation_test.go) |
| `TestRefusedRequestsAreNotRecorded` | Unit | A request the CA refuses anyway is not recorded. | [internal/ca/revocation_test.go](../../internal/ca/revocation_test.go) |
| `TestSignCRL` | Unit | A CRL is signed by the intermediate, lists each revoked serial number with its time and reason, has a sensible validity window, and can be empty. | [internal/ca/revocation_test.go](../../internal/ca/revocation_test.go) |
| `TestSignOCSP` | Unit | OCSP answers are signed for good, revoked (with time and reason) and unknown certificates; unknown wins over revoked; each answer has a limited validity. (1 sub-case) | [internal/ca/revocation_test.go](../../internal/ca/revocation_test.go) |
| `TestOCSPCacheIsBounded` | Unit | Questions about made-up serial numbers cannot fill the memory. | [internal/server/revcache_test.go](../../internal/server/revcache_test.go) |
| `TestWatchRevocationsStops` | Unit | The watcher stops with its context, and caching with it. | [internal/server/revcache_test.go](../../internal/server/revcache_test.go) |
| `FuzzOCSP` | Fuzz | Sends arbitrary OCSP requests, as a POST body and at the end of a GET address. The answer is never a server error, and always an OCSP answer. | [internal/server/fuzz_test.go](../../internal/server/fuzz_test.go) |
| `TestCertificatesFromACMEAndSCEPAreListed` | Integration | Certificates from ACME and SCEP are in the list like all others, and can be revoked. | [cmd/bxp/revoke_test.go](../../cmd/bxp/revoke_test.go) |
| `TestList` | Integration | bxp list certificates shows TLS and SSH certificates, the server's own certificate among them; with --revoked, nothing before a revocation, then only the revoked certificate with its reason. | [cmd/bxp/revoke_test.go](../../cmd/bxp/revoke_test.go) |
| `TestNoRevocationAddressesUnlessConfigured` | Integration | Without a public address configured, certificates name no addresses. | [cmd/bxp/revoke_test.go](../../cmd/bxp/revoke_test.go) |
| `TestPublicHTTPAddressOnlyHasPublicInformation` | Integration | The plain HTTP address must not issue anything. | [cmd/bxp/revoke_test.go](../../cmd/bxp/revoke_test.go) |
| `TestRevoke` | Integration | The whole road of a revocation, the way a relying party sees it: the certificate says where to ask, and the answers there change within seconds of the administrator revoking it. | [cmd/bxp/revoke_test.go](../../cmd/bxp/revoke_test.go) |
| `TestRevokeRefusesBadInput` | Integration | bxp revoke refuses an unknown reason, text that is not a serial number, and an unknown serial number, and revokes nothing. (1 sub-case) | [cmd/bxp/revoke_test.go](../../cmd/bxp/revoke_test.go) |
| `TestCACertificatesAndSSHKeys` | Integration | The public endpoints serve the root and intermediate certificates and the SSH user and host CA public keys, and never a private key. | [internal/server/public_test.go](../../internal/server/public_test.go) |
| `TestCRL` | Integration | The CRL lists a revoked certificate, with its reason, in the very next CRL, and lists nothing that was not revoked. | [internal/server/public_test.go](../../internal/server/public_test.go) |
| `TestDownloadCertificate` | Integration | An issued certificate can be downloaded by its serial number, written in lower or upper case or with 0x; an unknown serial number is not found, and text that is not one is refused. | [internal/server/public_test.go](../../internal/server/public_test.go) |
| `TestIssuedCertificatesAreInTheList` | Integration | Every way of getting a certificate ends up in the list. | [internal/server/public_test.go](../../internal/server/public_test.go) |
| `TestOCSP` | Integration | OCSP answers good for a fresh certificate, revoked with the reason after a revocation, and still good for the other certificates. | [internal/server/public_test.go](../../internal/server/public_test.go) |
| `TestOCSPDoesNotAnswerForASerialNumberAlone` | Integration | The same serial number at another CA must not borrow this CA's "good". | [internal/server/public_test.go](../../internal/server/public_test.go) |
| `TestOCSPFirstTakesUntidyPaths` | Integration | The same by hand, for certain: a path with // in the middle. | [internal/server/public_test.go](../../internal/server/public_test.go) |
| `TestOCSPForAnotherCA` | Integration | OCSP answers unknown for a certificate of another CA. | [internal/server/public_test.go](../../internal/server/public_test.go) |
| `TestOCSPForCertificatesTheCADoesNotKnow` | Integration | A certificate that is not in the CA's list must never get the answer "good", even if it looks as if this CA had issued it. | [internal/server/public_test.go](../../internal/server/public_test.go) |
| `TestOCSPGETWithDoubleSlash` | Integration | Base64 can contain "//". Such a request must still be answered, not redirected. Try many, so that some have it. | [internal/server/public_test.go](../../internal/server/public_test.go) |
| `TestOCSPMalformedRequests` | Integration | An empty, non-OCSP or too large OCSP request, and a GET with bad base64, get the standard malformed-request answer. | [internal/server/public_test.go](../../internal/server/public_test.go) |
| `TestOCSPWithGETAndSHA256` | Integration | OCSP over GET with a SHA-256 request, its base64 escaped, plain or URL- safe, answers revoked for a revoked certificate. | [internal/server/public_test.go](../../internal/server/public_test.go) |
| `TestPublicHandlerHasOnlyPublicInformation` | Integration | The plain HTTP address serves the public information and nothing else. | [internal/server/public_test.go](../../internal/server/public_test.go) |
| `TestCRLIsCachedUntilARevocation` | Integration | The CRL is signed once and cached, with Cache-Control, until a revocation; a revocation made by another process (bxp revoke) is picked up at the watcher's next look, and logged once. | [internal/server/revcache_test.go](../../internal/server/revcache_test.go) |
| `TestOCSPIsCachedUntilARevocation` | Integration | OCSP answers are cached, and a revocation made by another process shows in them after the watcher's next look. | [internal/server/revcache_test.go](../../internal/server/revcache_test.go) |
| `TestWatcherDoesNotLogOldRevocations` | Integration | Revocations from before the server started are not logged again. | [internal/server/revcache_test.go](../../internal/server/revcache_test.go) |
| `TestTLSAndRevocation` | E2E | A TLS certificate with a token, checked by openssl, then revoked and seen as revoked by openssl through OCSP and the CRL. | [test/e2e/core_test.go](../../test/e2e/core_test.go) |
<!-- END GENERATED CASES -->
