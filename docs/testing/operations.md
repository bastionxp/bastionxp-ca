# Operations: server, diagnostics, metrics, logs

## Scope

Running the server (start, health, stopping on SIGTERM), `bxp doctor`
and its support report, Prometheus metrics, the logs (text and JSON),
the `list` commands, the version, and the smoke test on every system.

## Risks

- A stop that loses records or answers half-done requests badly.
- `doctor` missing a problem, or its report holding secrets.
- Metrics readable without their token.
- Secrets in the logs.
- A version line that does not say what was built.

## Approach

- **Unit:** `doctor` finding problems, the report on a broken
  configuration, log formats, metric formatting, the version line, and the
  list commands' options.
- **Integration:** `doctor` on a healthy CA and its report (with no
  secret, name or comment from the configuration), metrics and their
  token, the list commands, health and unknown routes.
- **E2E:** `TestServerLifecycle` (reload, clean stop, restart);
  `TestGracefulStopUnderLoad` (SIGTERM during 60 requests: requests in
  flight finish, the database stays whole); `TestMetrics`;
  `TestDoctorFindsProblems`; `TestNoSecretsInLogs` (every log line JSON,
  no token, passphrase or key anywhere); `TestSmoke`, which also runs on
  macOS and Windows.

## Known gaps

- No load or performance tests.
- The systemd units are verified (`systemd-analyze verify`), not started;
  the container image is tested by `make test-container`, outside this
  table.

## Test cases

Run one case with `go test <package> -run '^Name$'`; see [Running the tests](README.md#running-the-tests).

<!-- BEGIN GENERATED CASES: go run ./test/spec -->
29 test cases: 11 unit, 12 integration, 6 e2e.

| Case | Level | Verifies | Location |
|---|---|---|---|
| `TestDoctorEncryptedKeys` | Unit | bxp doctor with encrypted keys warns when no passphrase is configured, checks that the keys open with the configured one, and fails when it is wrong. | [cmd/bxp/doctor_test.go](../../cmd/bxp/doctor_test.go) |
| `TestDoctorFindsProblems` | Unit | bxp doctor finds a missing key, a damaged database, open file permissions, an unreachable identity provider and a server that is not running. (1 sub-case) | [cmd/bxp/doctor_test.go](../../cmd/bxp/doctor_test.go) |
| `TestDoctorWithoutCA` | Unit | No CA at all: one clear failure, nothing else. | [cmd/bxp/doctor_test.go](../../cmd/bxp/doctor_test.go) |
| `TestListFormatChecked` | Unit | The list commands refuse an unknown --format. | [cmd/bxp/list_test.go](../../cmd/bxp/list_test.go) |
| `TestJSONLog` | Unit | JSON logs: one JSON object per line with the message and fields, and nothing below the level set. | [cmd/bxp/logging_test.go](../../cmd/bxp/logging_test.go) |
| `TestLoggerOptions` | Unit | An unknown log format or level is refused; every level is accepted, in any case. | [cmd/bxp/logging_test.go](../../cmd/bxp/logging_test.go) |
| `TestDoctorReportWithBrokenConfig` | Unit | A configuration that does not load still gives a report: the error and the file. | [cmd/bxp/report_test.go](../../cmd/bxp/report_test.go) |
| `TestBuildDetails` | Unit | bxp version shows the commit, local changes, the commit time in UTC, the Go version and the platform, and only the last two without git information. | [cmd/bxp/version_test.go](../../cmd/bxp/version_test.go) |
| `TestVersionFromLinkerFlags` | Unit | Set with -ldflags, as the container build does. | [cmd/bxp/version_test.go](../../cmd/bxp/version_test.go) |
| `TestFormat` | Unit | Metrics are written in the Prometheus text format, counters declared even before they have values. | [internal/metrics/metrics_test.go](../../internal/metrics/metrics_test.go) |
| `TestNilCountsNothing` | Unit | Code without metrics calls the same methods on nil. | [internal/metrics/metrics_test.go](../../internal/metrics/metrics_test.go) |
| `TestDoctorHealthy` | Integration | A running CA with a login and a public address: nothing fails. | [cmd/bxp/doctor_test.go](../../cmd/bxp/doctor_test.go) |
| `TestDoctorLDAP` | Integration | bxp doctor checks that the directory accepts the CA's service account, and fails with a wrong password. | [cmd/bxp/doctor_test.go](../../cmd/bxp/doctor_test.go) |
| `TestListACMEAccounts` | Integration | bxp list acme-accounts shows each account with its contact and creation date, as text and as JSON. | [cmd/bxp/list_test.go](../../cmd/bxp/list_test.go) |
| `TestListACMEOrders` | Integration | bxp list acme-orders shows orders with their names, status and challenge, without trailing spaces; --failed and --name filter them; JSON lists them newest first with their authorizations. | [cmd/bxp/list_test.go](../../cmd/bxp/list_test.go) |
| `TestListCertificatesJSON` | Integration | bxp list certificates --format json gives each certificate's fields, with the end time in a standard form. | [cmd/bxp/list_test.go](../../cmd/bxp/list_test.go) |
| `TestMetrics` | Integration | The metrics, behind their token and on their own address, count issued certificates by kind and verifier, logins, refusals, certificates by state, the CA certificates' expiry, the build, and requests by route; they contain no serial numbers or names. | [cmd/bxp/metrics_test.go](../../cmd/bxp/metrics_test.go) |
| `TestMetricsOffByDefault` | Integration | Without metrics.address there is no metrics endpoint. | [cmd/bxp/metrics_test.go](../../cmd/bxp/metrics_test.go) |
| `TestDoctorReport` | Integration | The report holds the checks, the configuration and the database's counts, and none of the secrets, people's names or comments. | [cmd/bxp/report_test.go](../../cmd/bxp/report_test.go) |
| `TestServeNeedsAnInitializedCA` | Integration | bxp serve refuses to start in a data directory without a CA. | [cmd/bxp/serve_test.go](../../cmd/bxp/serve_test.go) |
| `TestHandlerToken` | Integration | The metrics endpoint needs the right bearer token: none, a wrong one, or Basic gets 401. | [internal/metrics/metrics_test.go](../../internal/metrics/metrics_test.go) |
| `TestHealth` | Integration | GET /health answers 200 with {"status":"ok"}. | [internal/server/server_test.go](../../internal/server/server_test.go) |
| `TestUnknownRoutes` | Integration | Unknown addresses answer 404, and known ones with the wrong method 405. (1 sub-case) | [internal/server/server_test.go](../../internal/server/server_test.go) |
| `TestServerLifecycle` | E2E | The server as a process: reload on SIGHUP, a broken configuration ignored, a clean stop on SIGTERM, and everything still there after a restart. | [test/e2e/core_test.go](../../test/e2e/core_test.go) |
| `TestDoctorFindsProblems` | E2E | bxp doctor finds what is broken, and says so with its exit status. | [test/e2e/operations_test.go](../../test/e2e/operations_test.go) |
| `TestGracefulStopUnderLoad` | E2E | SIGTERM while requests are running: each one either gets its certificate or fails cleanly, the server exits cleanly, and afterwards the database is whole and knows every certificate a client got. | [test/e2e/operations_test.go](../../test/e2e/operations_test.go) |
| `TestMetrics` | E2E | The metrics endpoint counts what happens, and asks for its token. | [test/e2e/operations_test.go](../../test/e2e/operations_test.go) |
| `TestNoSecretsInLogs` | E2E | Nothing secret reaches the server's log or what the client commands print, even at the debug level: not the one-time tokens (they are passwords until used), not the passphrases, not a private key. And with --log-format json, every line is JSON, for log collectors. | [test/e2e/secrets_test.go](../../test/e2e/secrets_test.go) |
| `TestSmoke` | E2E | The basics on every system, Windows included: a CA, its server, and the client commands people use most. Checked with Go itself, not with openssl or ssh-keygen, which a Windows machine may not have. The other tests, with real clients and signals, run on Linux and macOS. | [test/e2e/smoke_test.go](../../test/e2e/smoke_test.go) |
<!-- END GENERATED CASES -->
