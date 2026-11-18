# One-time tokens

## Scope

One-time tokens: created with `bxp token` on the CA machine, or by the
server after a login; their format (a JWT signed with `token.key`); what
they allow (profile, names, subject); their lifetime; and their single
use. Also the checks of requested names against what a token allows.

## Risks

- A token used twice, or a forged, damaged or expired token accepted.
- A certificate for names the token does not give.
- A token for one kind of certificate used for another.
- A refused request that uses the token up, so the requester cannot try
  again.

## Approach

- **Unit:** issuing and verifying tokens; refusing damaged, expired,
  incomplete tokens and tokens from another key; every token's own ID;
  the subject; the token key created once even when many processes start
  together; login tokens and one-time tokens not interchangeable; the name
  checks for TLS and SSH; the `bxp token` command's input checks.
- **Fuzz:** `FuzzVerify`: no generated token is ever accepted.
- **Integration:** `TestInitTokenServe`, the whole road: init, token,
  server, certificate over HTTPS.
- **E2E:** `TestTokenLimits`: an expired token, names, extra names and an
  SSH principal the token does not give, and a TLS token for SSH are all
  refused with their reason, and a refused request does not use the token
  up. One use is checked in `TestTLSAndRevocation`, and across restarts in
  the Database chapter.

## Known gaps

- Clocks that differ between the CA and the requester are not tested.

## Test cases

Run one case with `go test <package> -run '^Name$'`; see [Running the tests](README.md#running-the-tests).

<!-- BEGIN GENERATED CASES: go run ./test/spec -->
32 test cases: 29 unit, 1 fuzz, 1 integration, 1 e2e.

| Case | Level | Verifies | Location |
|---|---|---|---|
| `TestTokenCommand` | Unit | The command as a person types it: on the CA machine it prints a token; with --ca-url it goes to the server and needs no configuration file. | [cmd/bxp/serve_test.go](../../cmd/bxp/serve_test.go) |
| `TestTokenIsRemote` | Unit | bxp token asks the server only on an admin's machine (--ca-url given, or BXP_CA_URL without a configuration file); on the CA machine it makes the token itself, even with BXP_CA_URL set. | [cmd/bxp/serve_test.go](../../cmd/bxp/serve_test.go) |
| `TestTokenNeedsAnInitializedCA` | Unit | bxp token refuses to make a token without a CA. | [cmd/bxp/serve_test.go](../../cmd/bxp/serve_test.go) |
| `TestTokenRejectsBadInput` | Unit | bxp token refuses an unknown profile, missing names, a lifetime above the maximum and a subject with a space, and prints no token when it refuses. (1 sub-case) | [cmd/bxp/serve_test.go](../../cmd/bxp/serve_test.go) |
| `TestCheckSSH` | Unit | An SSH request may ask only for allowed principals, exactly as written: not others, not another case, not an empty one. (1 sub-case) | [internal/policy/policy_test.go](../../internal/policy/policy_test.go) |
| `TestCheckX509` | Unit | A TLS request may ask only for names in the allowed list: DNS names (case does not matter), IP addresses (however written) and email addresses; not other names, subdomains, parents, wildcards not listed, or names a listed wildcard covers. (1 sub-case) | [internal/policy/policy_test.go](../../internal/policy/policy_test.go) |
| `TestCheckX509WithEmptyListAllowsNothing` | Unit | An empty list of allowed names allows no name at all. | [internal/policy/policy_test.go](../../internal/policy/policy_test.go) |
| `TestDerive` | Unit | Values derived for a login (the PKCE verifier, the nonce) are URL-safe, the same for the same input and key, different for another login, purpose or CA, and the same after a restart with the same key. | [internal/token/login_test.go](../../internal/token/login_test.go) |
| `TestIssueAndVerifyLogin` | Unit | A signed login state verifies back to exactly the login it was made from. | [internal/token/login_test.go](../../internal/token/login_test.go) |
| `TestIssueLoginGivesEachLoginAnID` | Unit | Each login gets its own ID, even when none is given. | [internal/token/login_test.go](../../internal/token/login_test.go) |
| `TestIssueLoginNeedsTheBasics` | Unit | A login state without a callback, client state, profile or provider is refused. (1 sub-case) | [internal/token/login_test.go](../../internal/token/login_test.go) |
| `TestLoginsAndOneTimeTokensAreNotInterchangeable` | Unit | Logins and one-time tokens are signed with the same key. Neither may be accepted in place of the other. | [internal/token/login_test.go](../../internal/token/login_test.go) |
| `TestVerifyLoginRejectsExpiredLogin` | Unit | A login state is accepted until LoginValidity ends and refused after. | [internal/token/login_test.go](../../internal/token/login_test.go) |
| `TestVerifyLoginRejectsIncompleteLogins` | Unit | A login state without an expiry, audience or callback is refused, while the same claims complete are accepted. (1 sub-case) | [internal/token/login_test.go](../../internal/token/login_test.go) |
| `TestVerifyLoginRejectsLoginsNotSignedByThisCA` | Unit | The callback in a login is where a token will be sent. Nobody but the CA may be able to write one. | [internal/token/login_test.go](../../internal/token/login_test.go) |
| `TestCreatedBy` | Unit | A token records who created it, separately from who it is for (the subject). | [internal/token/token_test.go](../../internal/token/token_test.go) |
| `TestEveryTokenHasItsOwnID` | Unit | Two tokens issued for the same thing have different IDs, so each can be used only once. | [internal/token/token_test.go](../../internal/token/token_test.go) |
| `TestIssueAndVerify` | Unit | A token issued for a profile, names and lifetime verifies back to exactly that profile, those names, the expiry it was given, and an ID. | [internal/token/token_test.go](../../internal/token/token_test.go) |
| `TestIssueRejectsBadInput` | Unit | Issuing refuses a missing profile, missing or empty names, a lifetime that is negative or above the maximum, and a subject with spaces, line breaks or too many characters. (1 sub-case) | [internal/token/token_test.go](../../internal/token/token_test.go) |
| `TestIssueUsesDefaultValidity` | Unit | A token issued without a lifetime expires after DefaultValidity. | [internal/token/token_test.go](../../internal/token/token_test.go) |
| `TestKeyFingerprint` | Unit | A token can be tied to a public key's fingerprint, and a token without one is tied to no key. | [internal/token/token_test.go](../../internal/token/token_test.go) |
| `TestLoadOrCreateKey` | Unit | The token key is created once, with mode 600, and loaded unchanged afterwards, so tokens keep working after a restart. | [internal/token/token_test.go](../../internal/token/token_test.go) |
| `TestLoadOrCreateKeyFromManyProgramsAtOnce` | Unit | Ten callers creating the token key at the same moment all get the same key, and no temporary files are left behind. | [internal/token/token_test.go](../../internal/token/token_test.go) |
| `TestLoadOrCreateKeyRejectsBadFile` | Unit | A damaged token key file is refused, not replaced. | [internal/token/token_test.go](../../internal/token/token_test.go) |
| `TestSubject` | Unit | The token's subject is the one given, or else the first name. (1 sub-case) | [internal/token/token_test.go](../../internal/token/token_test.go) |
| `TestVerifyRejectsDamagedTokens` | Unit | Damaged and forged tokens are refused: empty, not a token, without a signature, truncated, with trailing data, unsigned (alg none), and a payload swapped in from another token. (1 sub-case) | [internal/token/token_test.go](../../internal/token/token_test.go) |
| `TestVerifyRejectsExpiredToken` | Unit | A token is accepted until it expires and refused from the second after. | [internal/token/token_test.go](../../internal/token/token_test.go) |
| `TestVerifyRejectsIncompleteTokens` | Unit | A token missing any required claim (expiry, ID, issuer, subject, audience, profile, names), or meant for logins, is refused, while the same token complete is accepted. (1 sub-case) | [internal/token/token_test.go](../../internal/token/token_test.go) |
| `TestVerifyRejectsTokenFromAnotherKey` | Unit | A token signed with another CA's token key is refused. | [internal/token/token_test.go](../../internal/token/token_test.go) |
| `FuzzVerify` | Fuzz | Feeds arbitrary text to the token and login checks. They must never panic, and never accept anything this verifier did not sign: the fuzzer has no key, so whatever passes must be one of the seeds. | [internal/token/fuzz_test.go](../../internal/token/fuzz_test.go) |
| `TestInitTokenServe` | Integration | Walks through what an administrator does: create the CA, start the server, create a token, and get a certificate with it over HTTPS. | [cmd/bxp/serve_test.go](../../cmd/bxp/serve_test.go) |
| `TestTokenLimits` | E2E | One-time tokens give exactly what they name, for as long as they say, and a refused request does not use a token up. | [test/e2e/limits_test.go](../../test/e2e/limits_test.go) |
<!-- END GENERATED CASES -->
