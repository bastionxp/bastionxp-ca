# Database and backup

## Scope

The SQLite database: issued certificates, used tokens, ACME accounts and
orders; its schema version; opening it read-only for commands that only
look; and `bxp backup` and restoring a backup.

## Risks

- A token used twice after a restart, or by requests at the same moment.
- Records lost, or a "database is locked" error, when the server and
  commands use the database at the same time.
- An older version misreading a database a newer one wrote.
- A backup taken while the server runs that is incomplete.

## Approach

- **Unit:** every table's reads and writes, one use per token (also with
  many requests at once and across restarts), schema versions and newer
  databases refused, read-only opening, and the backup copy.
- **Integration:** backup and restore, and commands that look never
  updating the database.
- **E2E:** `TestConcurrentProcesses`: 150 issuances, 16 at a time, while
  `bxp revoke`, `bxp list` and `bxp backup` run in loops: no process fails,
  nothing is lost, every backup opens. `TestBackupAndRestore`: a backup
  taken while serving, restored in place, has everything from before it.

## Known gaps

- A full disk and a damaged database file are not tested.
- Upgrades between released versions are not tested yet: nothing is
  released.

## Test cases

Run one case with `go test <package> -run '^Name$'`; see [Running the tests](README.md#running-the-tests).

<!-- BEGIN GENERATED CASES: go run ./test/spec -->
37 test cases: 33 unit, 2 integration, 2 e2e.

| Case | Level | Verifies | Location |
|---|---|---|---|
| `TestACMEAccount` | Unit | An ACME account is created once, with its creation time, and found by ID or key thumbprint; the same key again returns the first account; unknown accounts and keys are not found. | [internal/store/acme_test.go](../../internal/store/acme_test.go) |
| `TestACMEAccountSameKeyManyRequestsAtOnce` | Unit | Many registrations with one key at the same time create one account, and all get it. | [internal/store/acme_test.go](../../internal/store/acme_test.go) |
| `TestACMELists` | Unit | The lists behind "bxp list acme-accounts" and "bxp list acme-orders". | [internal/store/acme_test.go](../../internal/store/acme_test.go) |
| `TestACMEOrderAndAuthzs` | Unit | An ACME order and its authorizations are saved and read back, pending; its certificate is found by serial number once issued, with its account; an empty serial number, unknown orders and unknown authorizations are not found. | [internal/store/acme_test.go](../../internal/store/acme_test.go) |
| `TestACMEOrderReplaces` | Unit | One certificate is replaced by one order (RFC 9773, section 5), unless that order failed or ran out of time. | [internal/store/acme_test.go](../../internal/store/acme_test.go) |
| `TestACMEOrderStatus` | Unit | An order is pending while proofs are missing, ready when all are proved, valid when issued, and invalid when a proof failed. | [internal/store/acme_test.go](../../internal/store/acme_test.go) |
| `TestChangeACMEAccountKey` | Unit | An account's key can be changed, not to another account's key; the old key no longer finds the account. | [internal/store/acme_test.go](../../internal/store/acme_test.go) |
| `TestCreateACMEOrderIsAllOrNothing` | Unit | An order is saved with all its authorizations or not at all. | [internal/store/acme_test.go](../../internal/store/acme_test.go) |
| `TestDeactivateACMEAccount` | Unit | An account is valid when created and deactivated after deactivation. | [internal/store/acme_test.go](../../internal/store/acme_test.go) |
| `TestExpiredACMEOrdersAreGone` | Unit | Expired orders and authorizations are not found, and are removed when the next order is created. | [internal/store/acme_test.go](../../internal/store/acme_test.go) |
| `TestFailedACMEOrdersAreKept` | Unit | Expired orders go with the next new order, except failed ones: they stay for KeepFailedACMEOrdersFor after they expire. | [internal/store/acme_test.go](../../internal/store/acme_test.go) |
| `TestFinishACMEAuthzDecidesOnce` | Unit | An authorization is decided once: a failed proof stays failed with its first error; it cannot go back to pending or to an unknown status. | [internal/store/acme_test.go](../../internal/store/acme_test.go) |
| `TestIssuedACMEOrdersStayWithTheirCertificate` | Unit | An expired order that got a certificate stays while the certificate is valid: it says which account may revoke or replace the certificate. | [internal/store/acme_test.go](../../internal/store/acme_test.go) |
| `TestBackupTo` | Unit | A backup is a complete copy at the current schema, with the data of the original, and never overwrites an existing file. | [internal/store/backup_test.go](../../internal/store/backup_test.go) |
| `TestOldCertificatesAreTidiedAway` | Unit | A certificate that expired long ago is removed when the next one is recorded. | [internal/store/certificates_test.go](../../internal/store/certificates_test.go) |
| `TestParseSSHSerial` | Unit | SSH serial numbers are read as decimal up to the largest 64-bit number, with spaces or leading zeros; negative, non-numeric, too large or two numbers are refused. | [internal/store/certificates_test.go](../../internal/store/certificates_test.go) |
| `TestParseX509Serial` | Unit | TLS serial numbers are read in lower or upper case, with colons, 0x, spaces or leading zeros; anything else is refused. | [internal/store/certificates_test.go](../../internal/store/certificates_test.go) |
| `TestRecordAndReadX509` | Unit | A recorded TLS certificate reads back with its profile, subject, names, PEM body and dates, not revoked; an unknown serial number, or the same number as an SSH certificate, is not found. | [internal/store/certificates_test.go](../../internal/store/certificates_test.go) |
| `TestRecordRefusesASerialNumberTwice` | Unit | Two certificates must never share a serial number. If the CA ever made one twice, the second must not be recorded, and so not be issued. | [internal/store/certificates_test.go](../../internal/store/certificates_test.go) |
| `TestRecordSSH` | Unit | A recorded SSH certificate reads back with its principals, body and end, even with the largest serial number an SSH certificate can have. | [internal/store/certificates_test.go](../../internal/store/certificates_test.go) |
| `TestRevokeSSH` | Unit | Revoking an SSH certificate is recorded, once, and does not put it on the CRL. | [internal/store/certificates_test.go](../../internal/store/certificates_test.go) |
| `TestRevokeX509` | Unit | Revoking a TLS certificate records the time and reason; a second revocation is refused and changes neither; an unknown serial number is not found. | [internal/store/certificates_test.go](../../internal/store/certificates_test.go) |
| `TestRevokeX509DoesNotTouchSSHCertificates` | Unit | Revoking a TLS serial number does not revoke an SSH certificate with the same number. | [internal/store/certificates_test.go](../../internal/store/certificates_test.go) |
| `TestRevokedX509AndList` | Unit | The CRL gets revoked certificates that have not expired; the list has every certificate, and the revoked list includes expired revoked ones. | [internal/store/certificates_test.go](../../internal/store/certificates_test.go) |
| `TestMigrationsRunOnce` | Unit | A database at an older schema gets the migrations it has not had, once, and keeps its data. (Shown with a made-up migration: the first release has only the first schema.) | [internal/store/migrate_test.go](../../internal/store/migrate_test.go) |
| `TestNewDatabaseGetsTheSchemaVersion` | Unit | A new database gets the current schema version, and opening it again changes nothing. | [internal/store/migrate_test.go](../../internal/store/migrate_test.go) |
| `TestNewerDatabaseIsRefused` | Unit | An older version must not touch a database a newer one wrote. | [internal/store/migrate_test.go](../../internal/store/migrate_test.go) |
| `TestOpenReadOnly` | Unit | A read-only open leaves the database as it is: an older one is not updated, nothing can be written, a missing one is not created, and a consistent copy can still be made. | [internal/store/migrate_test.go](../../internal/store/migrate_test.go) |
| `TestUseTokenIsRememberedAfterRestart` | Unit | A used token stays used after the database is reopened. | [internal/store/store_test.go](../../internal/store/store_test.go) |
| `TestUseTokenOnlyWorksOnce` | Unit | A token can be used once; another token is not affected. | [internal/store/store_test.go](../../internal/store/store_test.go) |
| `TestUseTokenRejectsEmptyID` | Unit | A token without an ID is refused. | [internal/store/store_test.go](../../internal/store/store_test.go) |
| `TestUseTokenRemovesExpiredRecords` | Unit | Records of expired tokens are removed. | [internal/store/store_test.go](../../internal/store/store_test.go) |
| `TestUseTokenWithManyRequestsAtOnce` | Unit | Many uses of one token at the same time: exactly one succeeds. | [internal/store/store_test.go](../../internal/store/store_test.go) |
| `TestBackupAndRestore` | Integration | A backup taken while the server runs is a working CA: restored, it knows the certificates issued before. | [cmd/bxp/backup_test.go](../../cmd/bxp/backup_test.go) |
| `TestLookingDoesNotUpdateTheDatabase` | Integration | The commands that only look (doctor, list certificates, backup) never update the database: a newer version run to look must not change it under the server that still runs. | [cmd/bxp/schema_test.go](../../cmd/bxp/schema_test.go) |
| `TestConcurrentProcesses` | E2E | The server and the commands on the CA machine use one SQLite file from separate processes. Under load, with revocations, lists and backups going on at the same time as issuance, no process fails, nothing is lost, and no "database is locked" reaches anyone. | [test/e2e/concurrency_test.go](../../test/e2e/concurrency_test.go) |
| `TestBackupAndRestore` | E2E | A backup taken while the server runs, restored into a fresh data directory: the server starts, knows what it knew then, revocation included, and issues again. | [test/e2e/maintenance_test.go](../../test/e2e/maintenance_test.go) |
<!-- END GENERATED CASES -->
