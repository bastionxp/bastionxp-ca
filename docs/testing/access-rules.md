# Access rules

## Scope

The `access` rules: who matches (users, groups), what they get (SSH
principals, admin), what logged-in people may request for themselves with
each verifier's profiles, and `bxp access check`.

## Risks

- Someone getting principals or admin rights through a rule meant for
  others: names and groups confused, case differences, placeholders.
- A user getting certificates for other people.

## Approach

- **Unit:** matching by user and by group, admins, principals and their
  placeholders, what may be asked for oneself, rules copied (not shared),
  and `bxp access check` (text, JSON, choosing the login).
- **Integration:** logins getting the verifier's profiles, and own client
  certificates with OIDC and LDAP.

## Known gaps

- None specific; the logins themselves are in the OIDC and LDAP chapters.

## Test cases

Run one case with `go test <package> -run '^Name$'`; see [Running the tests](README.md#running-the-tests).

<!-- BEGIN GENERATED CASES: go run ./test/spec -->
17 test cases: 14 unit, 3 integration.

| Case | Level | Verifies | Location |
|---|---|---|---|
| `TestAccessCheck` | Unit | bxp access check shows which rules match a user and what they get, as text and JSON: SSH principals and TLS certificates for a user in groups, admin for an admin, and a refusal when no rule matches. | [cmd/bxp/access_test.go](../../cmd/bxp/access_test.go) |
| `TestAccessCheckLogin` | Unit | bxp access check uses the one login that is set up, asks for --login when both are, refuses an unknown login, and needs --user. | [cmd/bxp/access_test.go](../../cmd/bxp/access_test.go) |
| `TestAdminWithoutPrincipalsMayLogIn` | Unit | An admin who is listed for nothing else may still log in. | [internal/policy/access_test.go](../../internal/policy/access_test.go) |
| `TestAuthorizeOwnCertificates` | Unit | What a login verifier gives people for themselves: its SSH profile for their own principals, and its X.509 profile for their own name only. | [internal/policy/access_test.go](../../internal/policy/access_test.go) |
| `TestAuthorizeTokenForThemselves` | Unit | A user gets a token for all or some of their own principals, always with themselves as the subject, whatever the case of their login. (1 sub-case) | [internal/policy/access_test.go](../../internal/policy/access_test.go) |
| `TestAuthorizeTokenLetsAdminsCreateAnything` | Unit | An admin may create a token for any profile, names and subject. | [internal/policy/access_test.go](../../internal/policy/access_test.go) |
| `TestAuthorizeTokenRefusesUsersWhatIsNotTheirs` | Unit | A user is refused someone else's principal or subject, a host certificate, TLS certificates, and so is an unknown or empty login; a refusal returns nothing. (1 sub-case) | [internal/policy/access_test.go](../../internal/policy/access_test.go) |
| `TestAuthorizeTokenWithGroups` | Unit | Tokens follow the groups: a group's principals are given, leaving the group takes them away, and an admin by group may hand out anything. | [internal/policy/access_test.go](../../internal/policy/access_test.go) |
| `TestMatches` | Unit | Matches tells which rules apply and why, with the test a login uses. | [internal/policy/access_test.go](../../internal/policy/access_test.go) |
| `TestMayLogInAndIsAdmin` | Unit | Who may log in and who is an admin, by name, ignoring case. | [internal/policy/access_test.go](../../internal/policy/access_test.go) |
| `TestNamesAndGroupsAreKeptApart` | Unit | Being in a group with a name like someone's login must not make the person that someone, and the reverse. | [internal/policy/access_test.go](../../internal/policy/access_test.go) |
| `TestNewAccessCopiesTheRules` | Unit | The rules a policy was made with cannot be changed from outside. | [internal/policy/access_test.go](../../internal/policy/access_test.go) |
| `TestRulesByGroup` | Unit | Access rules by group and by name: rules add up with each principal once, group names ignore case, an admin rule gives only admin, and no matching group gives nothing. (1 sub-case) | [internal/policy/access_test.go](../../internal/policy/access_test.go) |
| `TestShortUsernameWithoutAt` | Unit | {short_username} for a username without @ is the whole username. | [internal/policy/access_test.go](../../internal/policy/access_test.go) |
| `TestLoginUsesTheVerifierProfiles` | Integration | The verifier's cert_profiles decide what people get: here a short-lived client certificate with an OU, and an SSH profile that restricts where it may be used from. | [cmd/bxp/own_certs_test.go](../../cmd/bxp/own_certs_test.go) |
| `TestOwnCertificatesWithLDAP` | Integration | The same with a directory login: the profile comes from the ldap verifier, chosen by the CA, not by the command. | [cmd/bxp/own_certs_test.go](../../cmd/bxp/own_certs_test.go) |
| `TestOwnClientCertificateWithOIDC` | Integration | After a login, a person gets a TLS client certificate for themselves: the CA decides the name, and it is theirs. | [cmd/bxp/own_certs_test.go](../../cmd/bxp/own_certs_test.go) |
<!-- END GENERATED CASES -->
