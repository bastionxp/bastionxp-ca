# ACME

## Scope

The ACME server (RFC 8555): accounts, orders, authorizations, the
http-01, tls-alpn-01 and dns-01 challenges, finalizing, key change,
deactivation and revocation; IP identifiers (RFC 8738) and wildcards; the
allowed domains and IP ranges; the rate limits; renewal information and
`replaces` (RFC 9773); and the `bxp acme` client, also against other CAs.

## Risks

- A certificate for a name the client did not prove, or the CA may not
  issue for.
- Flaws in signed requests: nonces, signatures, account confusion.
- One account acting on another's orders or certificates.
- Limits that do not hold, or a client that waits silently when over one.
- Wrong renewal advice, or `replaces` abused.

## Approach

- **Unit:** the domain and IP policy, the rate limiter, renewal
  information IDs (with the RFC's own example), and the client's checks.
- **Fuzz:** `FuzzACME` (every signed endpoint never fails with a server
  error) and `FuzzCheckDomain` (never a name outside the allowed domains).
- **Integration:** the server with the ACME client from
  `golang.org/x/crypto` and fake hosts answering the challenges: every
  step, every refusal, wildcards, IP addresses, key change, deactivation,
  revocation, renewal information, `replaces`; and `bxp acme` against the
  server and against a fake CA.
- **E2E:** `TestACMEClients`: `bxp acme`, certbot, lego and acme.sh each
  issue, renew and revoke over http-01; certbot renews a revoked
  certificate through renewal information; lego and acme.sh send
  `replaces`. `TestACMEOtherChallenges`: tls-alpn-01 (bxp and lego), an IP
  address, a wildcard with dns-01 through a small DNS server, and an IP
  outside the allowed ranges. `TestACMERateLimits`: both limits, refused
  at once with the reason. `TestAutocert` and `TestCaddy`: ACME clients
  built into servers, with their own ACME code: a Go server with
  `autocert` gets its certificate during the first TLS handshake
  (tls-alpn-01) and reuses it after a restart; Caddy gets one for a site
  over http-01 and one over tls-alpn-01, and serves them to curl.
- **Integration (Docker):** `TestCertManager`: cert-manager in a Kubernetes
  cluster (kind), with BastionXP CA running there from its container image
  and a `ClusterIssuer` trusting its root through `caBundle`. dns-01 goes
  over RFC 2136 to a BIND server the CA asks. A certificate, a wildcard,
  a new certificate when the names change, and a refused name.

## Known gaps

- Traefik is not tested. It uses lego, which is.
- cert-manager is tested with dns-01 over RFC 2136 only, not with http-01
  through an Ingress, and once a week, not on every change.
- Renewal by autocert and Caddy is not tested: they renew on their own
  schedule (a third of the lifetime left), which a test cannot wait for.
- dns-01 is tested over UDP; DNS over TCP is not.

## Test cases

Run one case with `go test <package> -run '^Name$'`; see [Running the tests](README.md#running-the-tests).

<!-- BEGIN GENERATED CASES: go run ./test/spec -->
75 test cases: 9 unit, 2 fuzz, 57 integration, 1 integration (docker), 6 e2e.

| Case | Level | Verifies | Location |
|---|---|---|---|
| `TestExplainACMERateLimit` | Unit | A rate limit from the CA is explained with its message and when to try again (Retry-After as seconds or a date), and is not retried; a passing server error is retried; other errors are left as they are. | [cmd/bxp/acme_ari_test.go](../../cmd/bxp/acme_ari_test.go) |
| `TestACMEDeactivateNeedsYes` | Unit | Without a terminal to ask on, closing an account needs --yes. | [cmd/bxp/acme_manage_test.go](../../cmd/bxp/acme_manage_test.go) |
| `TestCertIDOfTheRFC` | Unit | The example of RFC 9773, section 4.1. | [internal/acme/ari_test.go](../../internal/acme/ari_test.go) |
| `TestWindowLimiter` | Unit | The rate limiter is full after its limit for that key only, says when to retry, and empties after its window. | [internal/acme/challenges_test.go](../../internal/acme/challenges_test.go) |
| `TestDirectResolver` | Unit | acme.dns_resolver: the lookup goes to that server, not to the machine's resolvers. | [internal/acme/dns01_test.go](../../internal/acme/dns01_test.go) |
| `TestReverseName` | Unit | The reverse names of IPv4 and IPv6 addresses, for tls-alpn-01. | [internal/acme/ip_test.go](../../internal/acme/ip_test.go) |
| `TestACMECheckDomain` | Unit | Which names ACME may issue for: the allowed domains and their subdomains, in any case, punycode and single-level wildcards; not other or look-alike domains, bare suffixes, other wildcard forms, IP addresses, trailing or empty dots, bad hyphens, underscores, spaces, paths, ports, email addresses or labels too long. | [internal/policy/acme_test.go](../../internal/policy/acme_test.go) |
| `TestACMECheckIP` | Unit | ACME may issue for IP addresses only in the configured ranges, and for none without ranges. | [internal/policy/acme_test.go](../../internal/policy/acme_test.go) |
| `TestACMEWithNoDomainsAllowsNothing` | Unit | With no domains configured, ACME may issue for no name. | [internal/policy/acme_test.go](../../internal/policy/acme_test.go) |
| `FuzzACME` | Fuzz | Sends arbitrary bodies to every signed ACME endpoint. Nobody needs a login to send these, so the server must never panic and never answer with a server error. | [internal/acme/fuzz_test.go](../../internal/acme/fuzz_test.go) |
| `FuzzCheckDomain` | Fuzz | Checks that every name the ACME policy accepts lies inside an allowed domain, whatever the fuzzer tries. | [internal/policy/fuzz_test.go](../../internal/policy/fuzz_test.go) |
| `TestACMERenewAsksTheCA` | Integration | "bxp acme renew" asks BastionXP CA when to renew: not yet for a fresh certificate, at once once it is revoked, without --force. | [cmd/bxp/acme_ari_test.go](../../cmd/bxp/acme_ari_test.go) |
| `TestACMERenewalDueWithoutRenewalInfo` | Integration | A CA without renewal information: the usual rule, a third of the lifetime. | [cmd/bxp/acme_ari_test.go](../../cmd/bxp/acme_ari_test.go) |
| `TestACMEDeactivateOnAnotherCA` | Integration | bxp acme deactivate on another ACME CA asks first: after a no the account stays, after a yes it is closed. | [cmd/bxp/acme_manage_test.go](../../cmd/bxp/acme_manage_test.go) |
| `TestACMEDeactivateOnBastionXPCA` | Integration | bxp acme deactivate closes the account: its key can no longer get certificates, and its certificates are not revoked. | [cmd/bxp/acme_manage_test.go](../../cmd/bxp/acme_manage_test.go) |
| `TestACMERenew` | Integration | bxp acme renew: a fresh certificate is not due and stays; forced, a new key and certificate for the same names, the --exec command run, and the account next to the certificate used again. | [cmd/bxp/acme_manage_test.go](../../cmd/bxp/acme_manage_test.go) |
| `TestACMERenewChecks` | Integration | bxp acme renew refuses missing files, the wrong key, and the dns-01 challenge. (1 sub-case) | [cmd/bxp/acme_manage_test.go](../../cmd/bxp/acme_manage_test.go) |
| `TestACMERevokeOnAnotherCA` | Integration | bxp acme revoke on another ACME CA, signed with the certificate's key or with the account key next to it, with the reason given; without either key it says to give --key. | [cmd/bxp/acme_manage_test.go](../../cmd/bxp/acme_manage_test.go) |
| `TestACMERevokeOnBastionXPCA` | Integration | Revocation over ACME on BastionXP CA's own CA: by the account, and with the certificate's key. | [cmd/bxp/acme_manage_test.go](../../cmd/bxp/acme_manage_test.go) |
| `TestACMERolloverKey` | Integration | bxp acme rollover-key replaces the account key (mode 600, no .new file left) and the new key works; a leftover from an earlier rollover stops it, the key unchanged. | [cmd/bxp/acme_manage_test.go](../../cmd/bxp/acme_manage_test.go) |
| `TestACME` | Integration | The whole road with ACME: one command, no token and no login. | [cmd/bxp/acme_test.go](../../cmd/bxp/acme_test.go) |
| `TestACMEChecksBeforeAskingTheCA` | Integration | bxp acme issue fails before asking the CA with no names, an existing key file without --force, no CA URL, a port that is taken, and a damaged account key. (1 sub-case) | [cmd/bxp/acme_test.go](../../cmd/bxp/acme_test.go) |
| `TestACMEFailsWithoutControlOfTheHost` | Integration | A machine that is not the host it names gets no certificate. | [cmd/bxp/acme_test.go](../../cmd/bxp/acme_test.go) |
| `TestACMEForAnIPAddress` | Integration | An IP address, with each challenge that can prove one. (1 sub-case) | [cmd/bxp/acme_test.go](../../cmd/bxp/acme_test.go) |
| `TestACMERefusedForNamesOutsideTheAllowedDomains` | Integration | bxp acme issue for a name or wildcard outside the allowed domains reports the CA's refusal, and the CA contacts no host. | [cmd/bxp/acme_test.go](../../cmd/bxp/acme_test.go) |
| `TestACMEWhenTheCAHasNoACME` | Integration | bxp acme issue fails against a CA without ACME. | [cmd/bxp/acme_test.go](../../cmd/bxp/acme_test.go) |
| `TestACMEWildcardNeedsDNS` | Integration | A wildcard needs dns-01, which this command cannot answer: it says so instead of failing later. | [cmd/bxp/acme_test.go](../../cmd/bxp/acme_test.go) |
| `TestACMEWithTLSALPN01` | Integration | tls-alpn-01: the CA connects to port 443, and the command answers with the challenge certificate. | [cmd/bxp/acme_test.go](../../cmd/bxp/acme_test.go) |
| `TestRevokeACMECertificate` | Integration | The administrator revokes an ACME certificate like any other. | [cmd/bxp/acme_test.go](../../cmd/bxp/acme_test.go) |
| `TestAccounts` | Integration | ACME accounts: a key without an account is told so; registering creates a valid account; the same key cannot register twice; a client with only the key finds its account again, with its contact. | [internal/acme/acme_test.go](../../internal/acme/acme_test.go) |
| `TestAccountsAreKeptApart` | Integration | One account must not see or use what belongs to another. | [internal/acme/acme_test.go](../../internal/acme/acme_test.go) |
| `TestChallengeFailures` | Integration | A client that cannot put the right answer on the host gets nothing. (1 sub-case) | [internal/acme/acme_test.go](../../internal/acme/acme_test.go) |
| `TestChangingContactsIsRefused` | Integration | Changing an account's contacts or deactivating it is refused as unsupported, and the account stays as it was. | [internal/acme/acme_test.go](../../internal/acme/acme_test.go) |
| `TestDirectoryAndNonce` | Integration | The directory lists every endpoint, renewal information included, and every nonce is different. | [internal/acme/acme_test.go](../../internal/acme/acme_test.go) |
| `TestFinalizeBeforeTheNamesAreProved` | Integration | An order cannot be finalized before its names are proved. | [internal/acme/acme_test.go](../../internal/acme/acme_test.go) |
| `TestFinalizeRefusesCSRsThatDoNotFitTheOrder` | Integration | The certificate may contain exactly the proved names, nothing more. (1 sub-case) | [internal/acme/acme_test.go](../../internal/acme/acme_test.go) |
| `TestIssueCertificate` | Integration | The whole road, driven by an independent ACME client. | [internal/acme/acme_test.go](../../internal/acme/acme_test.go) |
| `TestNewAccountChecks` | Integration | new-account must carry a key, not an account address; asking only for an existing account with an unknown key says it does not exist, and creates none. | [internal/acme/acme_test.go](../../internal/acme/acme_test.go) |
| `TestNoncesAreForgottenWhenUsedOrTooMany` | Integration | A nonce works once, an unknown nonce never; nonces collected without being used cannot grow the server's memory beyond a limit. | [internal/acme/acme_test.go](../../internal/acme/acme_test.go) |
| `TestOrderRefusesNamesTheCAMayNotIssue` | Integration | An order is refused for names outside the allowed domains (another domain, a look-alike, one bad name among good ones, a wildcard elsewhere, an invalid host name), for an IP address outside the configured ranges, and with no names; no host is contacted for a refused order. (1 sub-case) | [internal/acme/acme_test.go](../../internal/acme/acme_test.go) |
| `TestPublicURLIsUsedWhenSet` | Integration | With a public URL set, the directory's addresses start with it. | [internal/acme/acme_test.go](../../internal/acme/acme_test.go) |
| `TestRulesCanBeReplaced` | Integration | Replacing the allowed domains (a reload) takes effect for the next order. | [internal/acme/acme_test.go](../../internal/acme/acme_test.go) |
| `TestSignedRequestChecks` | Integration | Every signed ACME request is checked: a nonce works once and must be real; the signed URL must be this endpoint of this server; the signature must be the account's key, over the content sent; the account must exist and be this server's; only new-account may carry a key; shared-secret and unsigned requests, and requests that are too large, are refused. (12 sub-cases) | [internal/acme/acme_test.go](../../internal/acme/acme_test.go) |
| `TestOrderReplaces` | Integration | An order that replaces a certificate (RFC 9773): refused for another account, without a name in common, or with a malformed ID; accepted for the real renewal, which keeps saying what it replaces; a second replacement of the same certificate is alreadyReplaced. | [internal/acme/ari_test.go](../../internal/acme/ari_test.go) |
| `TestRenewalInfo` | Integration | Renewal information (RFC 9773): advertised in the directory; for a fresh certificate a window from two thirds to five sixths of its lifetime, with Retry-After; for a revoked one a window ending now; unknown certificates, another issuer's serial and malformed IDs are refused. | [internal/acme/ari_test.go](../../internal/acme/ari_test.go) |
| `TestAccountLimitPerAddress` | Integration | New accounts are limited per address; an existing account is still found. | [internal/acme/challenges_test.go](../../internal/acme/challenges_test.go) |
| `TestChallengesChangeForPendingAuthorizations` | Integration | A reload that takes a type away applies to pending authorizations too. | [internal/acme/challenges_test.go](../../internal/acme/challenges_test.go) |
| `TestChallengesOffered` | Integration | A name is offered http-01, dns-01 and tls-alpn-01; a wildcard only dns-01, with the base name and the wildcard flag (RFC 8555 7.1.4). | [internal/acme/challenges_test.go](../../internal/acme/challenges_test.go) |
| `TestChosenChallenges` | Integration | The administrator chooses the challenge types. | [internal/acme/challenges_test.go](../../internal/acme/challenges_test.go) |
| `TestDNS01` | Integration | dns-01: the right TXT record among others proves the name and the certificate is issued; nothing is fetched over HTTP; the decided challenge shows its status, the others stay pending. | [internal/acme/challenges_test.go](../../internal/acme/challenges_test.go) |
| `TestDNS01Failures` | Integration | dns-01 fails with no record, a wrong value, and the key authorization in place of its hash. (1 sub-case) | [internal/acme/challenges_test.go](../../internal/acme/challenges_test.go) |
| `TestKeyChange` | Integration | Key change (RFC 8555, section 7.3.5), with the client's own rollover: afterwards the account works with the new key only. | [internal/acme/challenges_test.go](../../internal/acme/challenges_test.go) |
| `TestOrderLimitPerAccount` | Integration | Orders are limited per account: over the limit, 429 rateLimited with Retry-After; another account is not affected. | [internal/acme/challenges_test.go](../../internal/acme/challenges_test.go) |
| `TestSetLimits` | Integration | Limits change while the server runs (configuration reload), and 0 means no limit. | [internal/acme/challenges_test.go](../../internal/acme/challenges_test.go) |
| `TestTLSALPN01` | Integration | tls-alpn-01: the right certificate on port 443 with acme-tls/1 proves the name and the certificate is issued. | [internal/acme/challenges_test.go](../../internal/acme/challenges_test.go) |
| `TestTLSALPN01Failures` | Integration | tls-alpn-01 fails with nothing on port 443, without acme-tls/1, with another account's certificate, with the extension not critical, and with a second name in the certificate. (1 sub-case) | [internal/acme/challenges_test.go](../../internal/acme/challenges_test.go) |
| `TestWildcardRefusesHTTP01` | Integration | http-01 cannot prove a wildcard, even if a client asks for it. | [internal/acme/challenges_test.go](../../internal/acme/challenges_test.go) |
| `TestWildcardWithDNS01` | Integration | A wildcard is proved through the TXT record of the name below it. | [internal/acme/challenges_test.go](../../internal/acme/challenges_test.go) |
| `TestWildcardWithoutDNS01` | Integration | Without dns-01, a wildcard is refused at the order. | [internal/acme/challenges_test.go](../../internal/acme/challenges_test.go) |
| `TestDNS01WithDNSServer` | Integration | The whole dns-01 road through a real DNS server. | [internal/acme/dns01_test.go](../../internal/acme/dns01_test.go) |
| `TestIPAddressRefusals` | Integration | An IP address outside the configured ranges is refused, and text that is not one is malformed; the CSR must carry the ordered address as an IP address. | [internal/acme/ip_test.go](../../internal/acme/ip_test.go) |
| `TestIPAddressWithHTTP01` | Integration | An IPv4 and an IPv6 address proved with http-01 (RFC 8738): ip identifiers, no dns-01 offered, and a certificate with the addresses as IP addresses, not DNS names. | [internal/acme/ip_test.go](../../internal/acme/ip_test.go) |
| `TestIPAddressWithTLSALPN01` | Integration | An IP address proved with tls-alpn-01, the CA asking for its reverse name (RFC 8738). | [internal/acme/ip_test.go](../../internal/acme/ip_test.go) |
| `TestCertificateKeys` | Integration | RFC 8555 section 11.1: no certificate may carry the key of any ACME account, not only the requesting one's. Reusing a certificate key in a new order (a renewal that keeps its key) is allowed: the RFC sets no rule for it. | [internal/acme/revoke_test.go](../../internal/acme/revoke_test.go) |
| `TestDeactivateAccount` | Integration | A deactivated account can neither order nor revoke, and its key opens neither it nor a new account; its certificate stays valid and can still be revoked with its own key. | [internal/acme/revoke_test.go](../../internal/acme/revoke_test.go) |
| `TestRevokeByTheAccount` | Integration | The account that ordered a certificate may revoke it; another account, or another key, may not; a reason the CA does not use is refused. | [internal/acme/revoke_test.go](../../internal/acme/revoke_test.go) |
| `TestRevokeOnlyOwnCertificates` | Integration | A certificate this CA did not issue, or a forged one with the serial of a real one, is refused. | [internal/acme/revoke_test.go](../../internal/acme/revoke_test.go) |
| `TestRevokeWithTheCertificateKey` | Integration | Anyone with the certificate's key may revoke it over ACME, without an account; a second revocation is alreadyRevoked. | [internal/acme/revoke_test.go](../../internal/acme/revoke_test.go) |
| `TestCertManager` | Integration (Docker) | cert-manager in a Kubernetes cluster gets certificates from BastionXP CA, running in the same cluster from its container image, through a ClusterIssuer with the CA's root as caBundle and dns-01 answered over RFC 2136 by a DNS server: a certificate, a wildcard, and a new certificate when the Certificate's names change, each verified with openssl; a name outside the CA's allowed domains is refused, and the order says why. (5 sub-cases) | [test/kubernetes/certmanager_test.go](../../test/kubernetes/certmanager_test.go) |
| `TestACMEClients` | E2E | Every ACME client gets a certificate from the real server, proving its name with http-01 on port 80. They run one after the other: they all need port 80. (5 sub-cases) | [test/e2e/acme_test.go](../../test/e2e/acme_test.go) |
| `TestACMEOtherChallenges` | E2E | The other ways to prove a name, with real clients: tls-alpn-01 on port 443, an IP address (RFC 8738), and a wildcard with dns-01, its TXT record written by lego's exec hook into a DNS server the CA asks. (5 sub-cases) | [test/e2e/challenges_test.go](../../test/e2e/challenges_test.go) |
| `TestFakeDNS` | E2E | Checks the fake against Go's resolver, so that a failure of the dns-01 test is not the fake's fault. | [test/e2e/dns_test.go](../../test/e2e/dns_test.go) |
| `TestACMERateLimits` | E2E | The ACME limits, with the real server and client: orders per account, and accounts per address. A client over a limit gets a clear refusal. (2 sub-cases) | [test/e2e/limits_test.go](../../test/e2e/limits_test.go) |
| `TestAutocert` | E2E | A Go web server with autocert gets its certificate from the real CA during the first TLS handshake, with tls-alpn-01 on port 443; curl and openssl accept it; after a restart the server uses the cached certificate without a new order. | [test/e2e/servers_test.go](../../test/e2e/servers_test.go) |
| `TestCaddy` | E2E | Caddy gets certificates from the real CA and serves them: one site set up as the documentation shows (a snippet with the tls directive's ca and ca_root, imported by the site), and two with their own ACME issuer, one proved only with http-01 and one only with tls-alpn-01; curl and openssl accept them. (1 sub-case) | [test/e2e/servers_test.go](../../test/e2e/servers_test.go) |
<!-- END GENERATED CASES -->
