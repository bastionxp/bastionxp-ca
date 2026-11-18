# Test specification

This is BastionXP CA's test specification: how the software is tested,
and every test case, feature by feature. It is for anyone who writes,
reviews or runs tests: read this page first, then the chapter of the
feature you work on.

The case tables in the chapters are generated from the tests themselves
(`go run ./test/spec`), so they always list exactly what exists. The text
around them is written by hand.

## Contents

1. [Scope](#scope)
2. [Test levels](#test-levels)
3. [Test doubles and fixtures](#test-doubles-and-fixtures)
4. [Running the tests](#running-the-tests)
5. [Continuous integration](#continuous-integration)
6. [Coverage at a glance](#coverage-at-a-glance), and the feature chapters
7. [Entry and exit criteria](#entry-and-exit-criteria)
8. [Conventions](#conventions)
9. [Adding a test](#adding-a-test)
10. [Known gaps](#known-gaps)

## Scope

**In scope:** everything in this repository: the CA and its keys, the
server and its HTTP API, the verifiers (one-time tokens, OIDC, LDAP, ACME,
SCEP, renewal), revocation (CRL, OCSP), the database, the configuration,
the `bxp` command line, and the packaging that ships with it (container
image, systemd units).

**Out of scope:**

- BastionXP Enterprise, which has its own tests.
- Load and performance testing. The concurrency test checks correctness
  under parallel use, not speed.
- Running the CA server on Windows: it is hosted on Linux. Windows is
  covered for the client commands and a smoke test only.

## Test levels

Every test case has one level. The level says what the test exercises and
what it needs to run.

| Level | What it exercises | Where it lives | Needs | Runs |
|---|---|---|---|---|
| **Unit** | One package's functions alone: parsing, policy decisions, key handling, certificate building. | `*_test.go` next to the code | nothing | `make test`, every push |
| **Fuzz** | A parser of untrusted input, with generated inputs, against an invariant ("never accepts a forged token", "never a server error"). | `fuzz_test.go` next to the parser | nothing | seeds with `make test`; fuzzing with `make fuzz` and weekly in CI |
| **Integration** | Several parts together, in one process: a real server on a loopback port, the CA, the database, the client code, and fakes of outside services (identity provider, directory, ACME hosts). | `*_test.go`, mostly in `cmd/bxp` and `internal/server` | nothing | `make test`, every push |
| **Integration (Docker)** | Real servers in containers: logins against Keycloak (OIDC) and Samba (Active Directory over LDAP), and cert-manager in a Kubernetes cluster (kind) with the CA running there from its container image. | `cmd/bxp/keycloak_test.go`, `internal/ldap/samba_test.go`, `test/kubernetes` | Docker | `make test-keycloak`, `make test-samba`, `make test-cert-manager`; weekly in CI |
| **E2E** | The real `bxp` binary, as separate processes, the way people run it, checked with programs other than BastionXP CA: openssl, curl, OpenSSH, certbot, lego, acme.sh, Caddy, Go's autocert, scepclient. | [`test/e2e`](../../test/e2e) | the clients (`make e2e-tools` installs them), ports 80 and 443 | `make test-e2e`, every push (Linux) |

A test is classified as Integration when it, or a helper it calls, starts
a server, a listener or a fake service.

**Why three levels.** Unit tests find a wrong decision quickly and say
exactly where. Integration tests find parts that do not fit together.
E2E tests find what only shows in the real program: flags, exit codes,
signals, files on disk, processes sharing the database, and whether other
software accepts the certificates. A behaviour is tested at the lowest
level that can show it, and once more end to end where users depend on it.

## Test doubles and fixtures

| Fixture | What it stands in for | Used by |
|---|---|---|
| `startTestCA` (`cmd/bxp`) | A complete CA with a server on a loopback port, OIDC through the fake provider, and ACME challenges sent to the test. | most integration tests of the command line |
| `newTestEnv` (`internal/acme`) | An ACME server with fake hosts that answer the CA's challenges (HTTP, TLS-ALPN, DNS). | ACME integration tests |
| [`oidctest`](../../internal/oidc/oidctest) | An OpenID Connect provider: discovery, login, tokens, groups. | OIDC tests |
| [`ldaptest`](../../internal/ldap/ldaptest) | An Active Directory domain controller over LDAPS and StartTLS, with nested groups and disabled accounts. | LDAP tests |
| [`catest`](../../internal/ca/catest) | A company root and issuing CA, for a CA under an external root. | external root tests |
| `newCA` / `start` ([`test/e2e`](../../test/e2e/harness_test.go)) | A CA made with the real `bxp init`, served by the real `bxp serve` in its own process. | all E2E tests |
| `startFakeDNS` (`test/e2e`) | A DNS server that answers the TXT records an ACME client's hook writes, for dns-01. | E2E dns-01 |
| `startKind` ([`test/kubernetes`](../../test/kubernetes)) | A Kubernetes cluster made with kind, deleted afterwards; `kubectl` runs inside its node. The test adds BIND as the DNS server for dns-01 over RFC 2136. | the cert-manager test |

Every test uses temporary directories (`t.TempDir()`) and loopback
addresses only. Unit and integration tests need no network access.

## Running the tests

```sh
make test                  # unit, fuzz seeds and integration: about a minute
make cover                 # statement coverage of the product code by unit and integration tests
make lint                  # vet, formatting, copyright headers, and this specification
make test-e2e              # E2E: installs the clients into .tools/ the first time
make test-keycloak         # OIDC against Keycloak (Docker)
make test-samba            # LDAP against Samba AD (Docker)
make test-cert-manager     # cert-manager in a kind cluster (Docker), a few minutes
make test-container        # the container image (Docker)
make fuzz                  # every fuzz target, 30 s each (FUZZTIME=5m for longer)
```

One case, by the name in the tables:

```sh
go test ./internal/acme -run '^TestRenewalInfo$' -v
go test -tags e2e ./test/e2e -run '^TestOpenSSHLogin$' -v     # after make e2e-tools
```

E2E tests need some machine setup, described in
[test/e2e/README.md](../../test/e2e/README.md): ports 80 and 443, `socat`,
`sshd`. A missing tool skips the test and says why; with
`BXP_E2E_REQUIRE_ALL=1`, as in CI, it fails it instead.

## Continuous integration

| Workflow | Job | When | Runs |
|---|---|---|---|
| `ci.yml` | `test` | every push and pull request | `make lint`, `make test`, and `systemd-analyze verify` of the units |
| `ci.yml` | `e2e` | every push and pull request | all E2E tests on Ubuntu, every tool required |
| `ci.yml` | `other-systems` | every push once the repository is public; by hand before | unit and integration tests, and `TestSmoke`, on macOS and Windows |
| `ci.yml` | `container` | every push and pull request | `make test-container` |
| `fuzz.yml` | `fuzz` | weekly, and by hand | every fuzz target for 5 minutes; a failing input is kept as an artifact |
| `integrations.yml` | `keycloak`, `samba`, `cert-manager` | weekly, and by hand | the Docker integration tests |
| `release.yml` | `test`, `image` | on a version tag | `make lint`, `go test -race ./...`, and the container smoke test before the image is pushed |

## Coverage at a glance

Test cases per feature and level. Each feature links to its chapter.

<!-- BEGIN GENERATED SUMMARY: go run ./test/spec -->
| Feature | Unit | Fuzz | Integration | Integration (Docker) | E2E | Total |
|---|---:|---:|---:|---:|---:|---:|
| [CA creation and hierarchy](ca.md) | 31 | 0 | 5 | 0 | 2 | 38 |
| [Key protection](key-protection.md) | 19 | 1 | 1 | 0 | 1 | 22 |
| [Certificate profiles](profiles.md) | 6 | 0 | 1 | 0 | 0 | 7 |
| [One-time tokens](tokens.md) | 29 | 1 | 1 | 0 | 1 | 32 |
| [TLS certificates](tls.md) | 9 | 1 | 18 | 0 | 1 | 29 |
| [SSH certificates](ssh.md) | 11 | 0 | 18 | 0 | 4 | 33 |
| [Renewal](renewal.md) | 2 | 1 | 17 | 0 | 2 | 22 |
| [Revocation, CRL and OCSP](revocation.md) | 11 | 1 | 22 | 0 | 1 | 35 |
| [ACME](acme.md) | 9 | 2 | 57 | 1 | 6 | 75 |
| [SCEP](scep.md) | 2 | 2 | 32 | 0 | 4 | 40 |
| [OIDC login](oidc.md) | 2 | 0 | 52 | 1 | 0 | 55 |
| [LDAP login](ldap.md) | 4 | 2 | 24 | 1 | 0 | 31 |
| [Access rules](access-rules.md) | 14 | 0 | 3 | 0 | 0 | 17 |
| [Configuration and reload](configuration.md) | 13 | 0 | 3 | 0 | 1 | 17 |
| [Database and backup](storage.md) | 33 | 0 | 2 | 0 | 2 | 37 |
| [Client connection and trust](client.md) | 7 | 0 | 14 | 0 | 2 | 23 |
| [Operations: server, diagnostics, metrics, logs](operations.md) | 11 | 0 | 12 | 0 | 6 | 29 |
| **All** | **213** | **11** | **282** | **3** | **33** | **542** |
<!-- END GENERATED SUMMARY -->

Each chapter has the same parts: **Scope** (what the feature is), **Risks**
(what must not go wrong), **Approach** (how each level covers it), **Known
gaps**, and the **Test cases**: name, level, what it verifies, and the file.

## Entry and exit criteria

**A change is ready for review when:**

- `make lint` and `make test` pass, and `make test-e2e` for changes to the
  command line, the server, or anything a client sees.
- New behaviour has a test; a bug fix has a test that fails without the
  fix.
- Code that reads untrusted input has a fuzz target, with an invariant.
- The specification is up to date (`go run ./test/spec`; `make lint`
  checks it).

**A release is ready when:**

- The tagged commit passed every job of `ci.yml` on `main`, including
  `e2e`, `container`, and `other-systems` (run by hand while the
  repository is private).
- The last weekly `fuzz` and `integrations` runs passed, or were run by
  hand for the release.
- The release workflow's own tests pass (`go test -race ./...`, the
  container smoke test).

## Conventions

- **Names say what is verified,** as a sentence: `TestTokenWorksOnlyOnce`,
  `TestReloadIgnoresABrokenConfiguration`. A **doc comment** says more
  when the name cannot; the specification shows it in place of the name.
- **Refusals are tested as carefully as successes.** Anything that rejects
  input has a test for the rejection, and for the message the user sees.
- **E2E tests check results with someone else's software,** not with
  BastionXP CA's own code: openssl verifies chains, OpenSSH logs in, certbot
  and lego get certificates.
- **No sleeps for timing.** Wait for the event: a log line, a port, a file.
  Where a wait is unavoidable (a token's expiry), it is short and stated.
- **Tests do not touch the developer's machine:** temporary directories,
  loopback addresses, `HOME` and `BXP_CLIENT_DIR` pointed into the test.
- **Never weaken a test to make it pass.** If a test is wrong, fix the
  test and say why in the change; if the product is wrong, fix the product.

## Adding a test

1. **Choose the level.** The lowest that can show the behaviour: a
   decision in one package is a unit test; a request through the server is
   an integration test; a flag, an exit code, a signal or another program's
   view is an E2E test.
2. **Put it next to similar tests.** Look in the feature's chapter for the
   files that test it.
3. **Name it as a sentence** of what it verifies, and add a doc comment if
   the name cannot say it all.
4. **Run it,** and make sure it fails without your change.
5. **Update the specification:** `go run ./test/spec`. A new test in an
   existing file is placed automatically. A new test file, or a test whose
   feature differs from its file, needs a rule in
   [`test/spec/features.go`](../../test/spec/features.go); `make lint`
   says which.
6. **Run `make lint` and `make test`** (and `make test-e2e` for E2E tests).

## Known gaps

What is not tested today, across features. Each chapter lists its own.

- **Windows:** the client commands and `TestSmoke` only; the CA server is
  not supported there.
- **Real identity providers:** OIDC is tested against a fake provider and
  against Keycloak, not against Entra ID, Okta, Google or AD FS. LDAP is
  tested against a fake directory and Samba, not against Windows Server
  Active Directory.
- **ACME clients:** certbot, lego, acme.sh, Caddy, Go's autocert and
  cert-manager are tested; Traefik is not (it uses lego). cert-manager is
  tested with dns-01 over RFC 2136, not with http-01 through an Ingress.
- **Performance:** no load tests and no timing thresholds.
- **systemd:** the units are checked with `systemd-analyze verify`, not
  started.
- **Releases:** the release workflow does not run the E2E tests itself; it
  relies on the tagged commit having passed CI on `main`.
