# OIDC login

## Scope

Login with an identity provider (OpenID Connect): the browser flow with
a callback on the requesting machine, the ID token and its claims
(username, groups, verified email), tokens tied to the requester's key,
remote tokens for admins, the client secret file, and a provider that is
down or a person who cancels.

## Risks

- A login completed by someone else: a forged or replayed callback, a
  missing or wrong state, a callback from another machine.
- A bad ID token accepted (wrong issuer, audience, signature, unverified
  email).
- A token from a login used for another key.
- A person getting certificates that are not theirs.

## Approach

- **Unit:** the remote token's input checks, and a provider that cannot
  be reached.
- **Integration:** with [`oidctest`](../../internal/oidc/oidctest) as the
  provider: reading the claims, the whole browser flow through the server
  and the command line, cancelling, Ctrl-C, a provider that is down, bad and missing ID
  tokens, wrong client secrets, callbacks the CA did not start, tokens
  only for their key, admins getting tokens for others, people not in the
  rules refused.
- **Integration (Docker):** `TestKeycloak` logs in to a real Keycloak,
  weekly in CI.

## Known gaps

- Entra ID, Okta, Google and AD FS are not tested; their documented
  settings are checked against the providers' documentation only.
- The browser is simulated; no real browser is driven.

## Test cases

Run one case with `go test <package> -run '^Name$'`; see [Running the tests](README.md#running-the-tests).

<!-- BEGIN GENERATED CASES: go run ./test/spec -->
55 test cases: 2 unit, 52 integration, 1 integration (docker).

| Case | Level | Verifies | Location |
|---|---|---|---|
| `TestRemoteTokenNeedsNames` | Unit | Asking for a token through a browser login needs --name. | [cmd/bxp/browser_test.go](../../cmd/bxp/browser_test.go) |
| `TestProviderUnreachable` | Unit | A provider that is down when the CA starts must not stop the CA; the logins fail until it is back. | [internal/oidc/oidc_test.go](../../internal/oidc/oidc_test.go) |
| `TestAdminGetsTokenWithBrowserLogin` | Integration | An admin gets a token from their own machine and hands it to a server, which uses it like any other token. | [cmd/bxp/browser_test.go](../../cmd/bxp/browser_test.go) |
| `TestAdminRequestsTLSWithBrowserLogin` | Integration | An admin gets a TLS certificate and key through a browser login. | [cmd/bxp/browser_test.go](../../cmd/bxp/browser_test.go) |
| `TestBrowserLoginCancelledAtTheProvider` | Integration | A browser login cancelled at the provider fails and says so. | [cmd/bxp/browser_test.go](../../cmd/bxp/browser_test.go) |
| `TestBrowserLoginIsRefusedForPeopleNotInTheConfiguration` | Integration | A browser login by someone not in the configuration fails with the CA's refusal, by name. | [cmd/bxp/browser_test.go](../../cmd/bxp/browser_test.go) |
| `TestBrowserLoginStopsOnCtrlC` | Integration | A command waiting for a browser login stops when interrupted. | [cmd/bxp/browser_test.go](../../cmd/bxp/browser_test.go) |
| `TestBrowserLoginUserIsHeldToTheirOwnPrincipals` | Integration | After a browser login, a user cannot get someone else's principal, a host certificate, a TLS certificate or a token for someone else; the command and the browser page both say it is not allowed, and no certificate file is written. (1 sub-case) | [cmd/bxp/browser_test.go](../../cmd/bxp/browser_test.go) |
| `TestBrowserLoginWhenLoginIsNotSetUp` | Integration | Against a CA without a login, the command says to use --token at once, without opening a browser. | [cmd/bxp/browser_test.go](../../cmd/bxp/browser_test.go) |
| `TestCallbackIgnoresRepliesThatAreNotFromThisLogin` | Integration | Any web page can make a person's browser call an address on 127.0.0.1. A reply that does not carry the secret state of this login must be ignored, and the command must keep waiting for the real one. | [cmd/bxp/browser_test.go](../../cmd/bxp/browser_test.go) |
| `TestLoginAddressNamesTheKeyAndAnAddressOnThisMachine` | Integration | What the command sends to the CA when it starts a login. | [cmd/bxp/browser_test.go](../../cmd/bxp/browser_test.go) |
| `TestNoBrowserWhenATokenIsGiven` | Integration | With --token there is no login: the browser must stay closed. | [cmd/bxp/browser_test.go](../../cmd/bxp/browser_test.go) |
| `TestRemoteTokenIgnoresAGivenToken` | Integration | "bxp token" from afar always logs in. A one-time token given with --token must not be used to make another token. | [cmd/bxp/browser_test.go](../../cmd/bxp/browser_test.go) |
| `TestSSHWithBrowserLogin` | Integration | The main road for a user: one command, a login in the browser, an SSH certificate. | [cmd/bxp/browser_test.go](../../cmd/bxp/browser_test.go) |
| `TestOIDCClientSecretFile` | Integration | The client secret can come from a file, so the configuration holds none. | [cmd/bxp/oidc_test.go](../../cmd/bxp/oidc_test.go) |
| `TestOIDCPersonWithoutAMatchingGroup` | Integration | bxp ssh through an OIDC login by someone in no matching group is refused. | [cmd/bxp/oidc_test.go](../../cmd/bxp/oidc_test.go) |
| `TestRemoteTokenWithOIDCAdmin` | Integration | An admin by group gets a token for a server from their own machine. | [cmd/bxp/oidc_test.go](../../cmd/bxp/oidc_test.go) |
| `TestSSHWithOIDCLogin` | Integration | With an identity provider set up, "bxp ssh" logs in there by itself. | [cmd/bxp/oidc_test.go](../../cmd/bxp/oidc_test.go) |
| `TestClaims` | Integration | The username and groups claims: no groups claim, one group as a string; a missing or empty name, or groups that are not a list, are errors. (1 sub-case) | [internal/oidc/oidc_test.go](../../internal/oidc/oidc_test.go) |
| `TestEmailMustBeVerified` | Integration | With the email address as the name, the provider must say it checked the address. Otherwise anyone could log in with a chosen address. (1 sub-case) | [internal/oidc/oidc_test.go](../../internal/oidc/oidc_test.go) |
| `TestLogin` | Integration | An OIDC login returns the state, the username in lower case and the groups; a code works only once. | [internal/oidc/oidc_test.go](../../internal/oidc/oidc_test.go) |
| `TestLoginNeedsTheRightVerifier` | Integration | The provider must hand out a code only to the one who knows the PKCE verifier: a code that leaks from the browser is of no use. | [internal/oidc/oidc_test.go](../../internal/oidc/oidc_test.go) |
| `TestLoginRefusesBadIDTokens` | Integration | An ID token signed with an unknown key, for another application, from another issuer, expired, for another login's nonce, or with too many groups fails the login, with no identity. (1 sub-case) | [internal/oidc/oidc_test.go](../../internal/oidc/oidc_test.go) |
| `TestLoginWithoutIDToken` | Integration | A provider answer without an ID token fails the login, with no identity. | [internal/oidc/oidc_test.go](../../internal/oidc/oidc_test.go) |
| `TestPreferredUsernameNeedsNoEmailVerified` | Integration | The check is for the email claim only. A claim the provider controls, such as preferred_username, needs no email_verified. | [internal/oidc/oidc_test.go](../../internal/oidc/oidc_test.go) |
| `TestWrongClientSecret` | Integration | A wrong client secret is reported as a configuration error, not a failed login, and the error does not contain the secret. | [internal/oidc/oidc_test.go](../../internal/oidc/oidc_test.go) |
| `TestAdminGetsTokensForOthers` | Integration | An admin's login gets a token for a server: for the subject chosen, created by the admin, bound to no key, valid for the time asked; it gets a host certificate. | [internal/server/login_flow_test.go](../../internal/server/login_flow_test.go) |
| `TestCallbackOnlyAcceptsLoginsTheCAStarted` | Integration | The second address a browser reaches, the callback, must not trust anything that the CA did not sign itself at the first one. (1 sub-case) | [internal/server/login_flow_test.go](../../internal/server/login_flow_test.go) |
| `TestCallbackWithAMadeUpCode` | Integration | Someone who builds the callback address by hand, with a state the CA did sign but a code the provider never gave out, gets no token. | [internal/server/login_flow_test.go](../../internal/server/login_flow_test.go) |
| `TestLoginEndpointsWhenNotSetUp` | Integration | Without a login configured, the login endpoints say it is not set up (404). | [internal/server/login_flow_test.go](../../internal/server/login_flow_test.go) |
| `TestLoginNeedsAState` | Integration | A login without a state is refused with 400. | [internal/server/login_flow_test.go](../../internal/server/login_flow_test.go) |
| `TestLoginOnlyAcceptsCallbacksOnTheSameMachine` | Integration | The callback is where a person's token is sent after an honest login. If the CA accepted an address that is not on the person's own machine, a link to the real CA could be used to steal tokens. (1 sub-case) | [internal/server/login_flow_test.go](../../internal/server/login_flow_test.go) |
| `TestLoginRefusesPeopleNotInTheConfiguration` | Integration | A correct login at the provider by someone not in the CA's configuration is refused, by name. | [internal/server/login_flow_test.go](../../internal/server/login_flow_test.go) |
| `TestLoginReportsBadRequestsToTheProgram` | Integration | Bad login requests are reported back to the program: an unknown profile or token validity before the trip to the provider; no names, a validity above the maximum, or a subject with a space after it. (2 sub-cases) | [internal/server/login_flow_test.go](../../internal/server/login_flow_test.go) |
| `TestLoginSendsTheBrowserToTheProvider` | Integration | The login address sends the browser to the provider with the right parameters, and without the client secret. | [internal/server/login_flow_test.go](../../internal/server/login_flow_test.go) |
| `TestLoginWhenTheProviderIsDown` | Integration | When the provider is down at the callback, the program is told to try again later. | [internal/server/login_flow_test.go](../../internal/server/login_flow_test.go) |
| `TestPersonCancelsAtTheProvider` | Integration | A login cancelled at the provider is reported to the program as cancelled. | [internal/server/login_flow_test.go](../../internal/server/login_flow_test.go) |
| `TestRulesCanBeReplaced` | Integration | The rules can change while the server runs: someone taken out of the configuration cannot log in any more, without a restart. | [internal/server/login_flow_test.go](../../internal/server/login_flow_test.go) |
| `TestSignedLoginIsNotAOneTimeToken` | Integration | A signed login is not a one-time token. It must not work at the sign endpoints, although it names a template and names like a token does. | [internal/server/login_flow_test.go](../../internal/server/login_flow_test.go) |
| `TestTLSTokenFromLoginOnlyWorksForItsKey` | Integration | A TLS token from a browser login that names the key's fingerprint works only for a CSR of that key, not for another key with the same names. | [internal/server/login_flow_test.go](../../internal/server/login_flow_test.go) |
| `TestTokenFromLoginOnlyWorksForItsKey` | Integration | A token from a login is tied to the key it was asked for. Whoever gets hold of it cannot use it for a key of their own. | [internal/server/login_flow_test.go](../../internal/server/login_flow_test.go) |
| `TestUserCannotGetWhatIsNotTheirs` | Integration | A user who logs in cannot get someone else's principal or subject, a host certificate, or a TLS certificate: each is not allowed. (1 sub-case) | [internal/server/login_flow_test.go](../../internal/server/login_flow_test.go) |
| `TestUserGetsOwnSSHCertificate` | Integration | The whole road for a user: log in, get a token, get an SSH certificate. | [internal/server/login_flow_test.go](../../internal/server/login_flow_test.go) |
| `TestAccessRulesCanBeReplaced` | Integration | Replacing the access rules (a reload) takes effect for the next login. | [internal/server/oidc_test.go](../../internal/server/oidc_test.go) |
| `TestLoginForAnotherProviderIsRefused` | Integration | A signed login started for another provider must not be finished here. | [internal/server/oidc_test.go](../../internal/server/oidc_test.go) |
| `TestOIDCAdminByGroup` | Integration | Membership of the admin group lets an OIDC user get host tokens, recorded as created by that user. | [internal/server/oidc_test.go](../../internal/server/oidc_test.go) |
| `TestOIDCEndpointsWhenNotSetUp` | Integration | Without OIDC configured, the login endpoints say it is not set up (404). | [internal/server/oidc_test.go](../../internal/server/oidc_test.go) |
| `TestOIDCLeavingAGroup` | Integration | Leaving a group at the provider takes the principal away at the next login, with no change to the CA. | [internal/server/oidc_test.go](../../internal/server/oidc_test.go) |
| `TestOIDCLoginGetsPrincipalsFromGroups` | Integration | The whole road: log in at the company's identity provider, get an SSH certificate with the principals the person's groups give. | [internal/server/oidc_test.go](../../internal/server/oidc_test.go) |
| `TestOIDCLoginRefusesBadIDTokens` | Integration | A bad ID token at the provider's end must end in a refusal for the program, never in a token. (1 sub-case) | [internal/server/oidc_test.go](../../internal/server/oidc_test.go) |
| `TestOIDCLoginWithoutAMatchingGroup` | Integration | An OIDC user in no group that an access rule names is refused, by name. | [internal/server/oidc_test.go](../../internal/server/oidc_test.go) |
| `TestOIDCPersonCancels` | Integration | An OIDC login cancelled at the provider is reported as cancelled. | [internal/server/oidc_test.go](../../internal/server/oidc_test.go) |
| `TestOIDCProviderDown` | Integration | When the OIDC provider is down at the start of a login, the program is told to try again later. | [internal/server/oidc_test.go](../../internal/server/oidc_test.go) |
| `TestOIDCVerifierNeverReachesTheBrowser` | Integration | The PKCE verifier must never be visible to the browser: not in the address sent to the provider, and not in the state. | [internal/server/oidc_test.go](../../internal/server/oidc_test.go) |
| `TestKeycloak` | Integration (Docker) | Browser logins against a real Keycloak: principals from a group, then a second login without the form; principals from a rule by name; no matching rule refused; an admin by group gets a host token; a non-admin is refused one. (5 sub-cases) | [cmd/bxp/keycloak_test.go](../../cmd/bxp/keycloak_test.go) |
<!-- END GENERATED CASES -->
