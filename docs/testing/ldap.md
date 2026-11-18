# LDAP login

## Scope

Login with a directory username and password (Active Directory or LDAP),
over LDAPS or StartTLS: finding the user, checking the password, reading
the groups (nested, as Active Directory does), limits on failed logins,
and `--password-stdin`.

## Risks

- LDAP filter injection through the username.
- An empty password sent as an unauthenticated bind, which directories
  accept as success.
- Trusting a directory's certificate that should not be trusted.
- Password guessing.
- The wrong person found (ambiguous names), or a disabled account
  accepted.

## Approach

- **Unit:** the command line's login flags and password input.
- **Fuzz:** `FuzzUserFilter` and `FuzzGroupFilter`: the filter always
  searches for exactly what was typed.
- **Integration:** with [`ldaptest`](../../internal/ldap/ldaptest) as the
  directory: logins, wrong passwords, unknown and disabled users,
  ambiguous names, `sAMAccountName`, StartTLS, an unknown certificate,
  the directory down, failure limits per user and per address, nested
  groups, and the login through the server and the command line.
- **Integration (Docker):** `TestSamba` against a Samba Active Directory
  domain controller, weekly in CI.

## Known gaps

- Windows Server Active Directory, OpenLDAP and FreeIPA are not tested.

## Test cases

Run one case with `go test <package> -run '^Name$'`; see [Running the tests](README.md#running-the-tests).

<!-- BEGIN GENERATED CASES: go run ./test/spec -->
31 test cases: 4 unit, 2 fuzz, 24 integration, 1 integration (docker).

| Case | Level | Verifies | Location |
|---|---|---|---|
| `TestLDAPChangeNeedsRestart` | Unit | A change to the LDAP settings is reported as needing a restart, not a reload. | [cmd/bxp/ldap_test.go](../../cmd/bxp/ldap_test.go) |
| `TestLDAPClientNeedsItsFiles` | Unit | The LDAP settings are refused with a missing or empty bind password file, a missing CA file, or a CA file without a PEM certificate. (1 sub-case) | [cmd/bxp/ldap_test.go](../../cmd/bxp/ldap_test.go) |
| `TestLoginFlagsThatDoNotGoTogether` | Unit | --ldap and --token together, and --ldap-user or --password-stdin without --ldap, are refused. | [cmd/bxp/ldap_test.go](../../cmd/bxp/ldap_test.go) |
| `TestPasswordFromStdin` | Unit | With --password-stdin, the first line of the standard input is the password, as in: cat ~/.ad-password \| bxp ssh --ldap --password-stdin ... | [cmd/bxp/ldap_test.go](../../cmd/bxp/ldap_test.go) |
| `FuzzGroupFilter` | Fuzz | Checks that the DN of the person's entry, which comes from the directory, cannot change the group search: the filter always has the same shape, with the DN, unchanged, as the in-chain match. | [internal/ldap/fuzz_test.go](../../internal/ldap/fuzz_test.go) |
| `FuzzUserFilter` | Fuzz | Checks that no username can change the search: the filter always compiles to the same shape, with the username, unchanged, as the value of the one equality test. | [internal/ldap/fuzz_test.go](../../internal/ldap/fuzz_test.go) |
| `TestLDAPLoginNotSetUp` | Integration | bxp ssh with an LDAP login against a CA without LDAP says it is not set up. | [cmd/bxp/ldap_test.go](../../cmd/bxp/ldap_test.go) |
| `TestRemoteTokenWithLDAPAdmin` | Integration | An admin by AD group gets a token for a server from their own machine. | [cmd/bxp/ldap_test.go](../../cmd/bxp/ldap_test.go) |
| `TestSSHWithLDAPLogin` | Integration | bxp ssh with an LDAP login gets a valid certificate for the user's principal, with the username in the key ID. | [cmd/bxp/ldap_test.go](../../cmd/bxp/ldap_test.go) |
| `TestSSHWithWrongLDAPPassword` | Integration | bxp ssh with a wrong LDAP password fails with the CA's refusal. | [cmd/bxp/ldap_test.go](../../cmd/bxp/ldap_test.go) |
| `TestAmbiguousMatch` | Integration | A filter that matches more than one person does not say who logs in. | [internal/ldap/ldap_test.go](../../internal/ldap/ldap_test.go) |
| `TestDirectoryDown` | Integration | A directory that cannot be reached is a connection error, not a failed login. | [internal/ldap/ldap_test.go](../../internal/ldap/ldap_test.go) |
| `TestDisabledAccount` | Integration | A disabled account fails the login without its password being tried. | [internal/ldap/ldap_test.go](../../internal/ldap/ldap_test.go) |
| `TestEmptyPasswordIsNeverSent` | Integration | AD takes a name with an empty password as an anonymous login and says "success". The client must not even ask. | [internal/ldap/ldap_test.go](../../internal/ldap/ldap_test.go) |
| `TestFilterInjection` | Integration | Special characters in the username must not change the search. | [internal/ldap/ldap_test.go](../../internal/ldap/ldap_test.go) |
| `TestLogin` | Integration | An LDAP login returns the user's principal name and groups, nested groups included, by name and DN; groups outside the group base DN do not count. | [internal/ldap/ldap_test.go](../../internal/ldap/ldap_test.go) |
| `TestLoginWithStartTLS` | Integration | An LDAP login over StartTLS. | [internal/ldap/ldap_test.go](../../internal/ldap/ldap_test.go) |
| `TestSAMAccountNameAsUsername` | Integration | sAMAccountName can be the username instead of the principal name. | [internal/ldap/ldap_test.go](../../internal/ldap/ldap_test.go) |
| `TestTooManyFailures` | Integration | After repeated failures for a name, in any case, even the right password is not passed to the directory, so it does not lock the account; other names are not affected. | [internal/ldap/ldap_test.go](../../internal/ldap/ldap_test.go) |
| `TestTooManyFailuresFromOneAddress` | Integration | Many failures from one address block further logins from it, not from other addresses. | [internal/ldap/ldap_test.go](../../internal/ldap/ldap_test.go) |
| `TestUnknownCertificate` | Integration | The directory's certificate is checked: the password must not go to an impostor. | [internal/ldap/ldap_test.go](../../internal/ldap/ldap_test.go) |
| `TestUnknownUser` | Integration | An unknown user fails the login, like a wrong password. | [internal/ldap/ldap_test.go](../../internal/ldap/ldap_test.go) |
| `TestWrongPassword` | Integration | A wrong password fails the login. | [internal/ldap/ldap_test.go](../../internal/ldap/ldap_test.go) |
| `TestWrongServicePassword` | Integration | A wrong service account is the CA's mistake: it must not look like the person's wrong password, nor count against them. | [internal/ldap/ldap_test.go](../../internal/ldap/ldap_test.go) |
| `TestLDAPAdminByNestedGroup` | Integration | Membership of the admin group through a nested group lets an LDAP user get a token for a server, valid for the time asked. | [internal/server/ldap_login_test.go](../../internal/server/ldap_login_test.go) |
| `TestLDAPDirectoryDown` | Integration | When the directory is down, an LDAP login gets 502 and a message about the directory. | [internal/server/ldap_login_test.go](../../internal/server/ldap_login_test.go) |
| `TestLDAPLoginGetsPrincipalsFromGroups` | Integration | The whole road: a directory password, the principals from AD groups, an SSH certificate. | [internal/server/ldap_login_test.go](../../internal/server/ldap_login_test.go) |
| `TestLDAPLoginNotSetUp` | Integration | Without LDAP configured, the LDAP login endpoint says it is not set up (404). | [internal/server/ldap_login_test.go](../../internal/server/ldap_login_test.go) |
| `TestLDAPLoginRefusals` | Integration | LDAP logins are refused, with status and message, for a wrong or empty password, an unknown person, no matching rule, a non-admin asking for a host certificate, a principal not given, a bad profile and a bad validity. (1 sub-case) | [internal/server/ldap_login_test.go](../../internal/server/ldap_login_test.go) |
| `TestLDAPTooManyFailures` | Integration | After repeated wrong passwords, LDAP logins for the name are refused with 429 even with the right password. | [internal/server/ldap_login_test.go](../../internal/server/ldap_login_test.go) |
| `TestSamba` | Integration (Docker) | LDAP logins against a real Samba Active Directory: nested groups, StartTLS, sAMAccountName as the username; an empty password, a wrong password, a disabled account, an unknown user, a wildcard and a filter injection all fail; a wrong service password and an unknown server certificate are errors; the CA's failure limit keeps the directory from locking the account. (9 sub-cases) | [internal/ldap/samba_test.go](../../internal/ldap/samba_test.go) |
<!-- END GENERATED CASES -->
