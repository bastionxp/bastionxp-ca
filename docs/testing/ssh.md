# SSH certificates

## Scope

SSH user and host certificates: through tokens and logins, principals,
validity, the key ID, key types, `bxp ssh` with files and with
`--agent`, `bxp trust --ssh`, and replacing an SSH CA key in two steps.

## Risks

- A certificate for a principal the token or the access rules do not
  give, for example `root`.
- A user certificate where a host certificate was asked for, or the
  reverse.
- Extensions or options from one profile in another.
- With `--agent`, a key written to disk.
- Replacing an SSH CA key that locks people out.

## Approach

- **Unit:** issuing user and host certificates, accepted key types,
  refusals, profiles and their extensions, the replaced host CA keys.
- **Integration:** the signing endpoint and its refusals; tokens only for
  their own kind of certificate; the key ID from the subject and the token;
  `bxp ssh` with files, with an in-memory agent, and with a passphrase-
  protected key; replacing the host CA key.
- **E2E:** `TestSSH` checks certificates with `ssh-keygen -L`;
  `TestOpenSSHLogin` logs in to a real `sshd` with a certificate, trusting
  the host through `bxp trust --ssh`, and is refused for another
  principal, without a certificate, and without the trust line;
  `TestSSHAgent` uses a real `ssh-agent`; `TestNewSSHUserCA` replaces the
  user CA key in both steps while logins keep working.

## Known gaps

- Replacing the host CA key is tested by integration tests, not end to
  end.
- Security keys (`sk-` keys) are not tested.

## Test cases

Run one case with `go test <package> -run '^Name$'`; see [Running the tests](README.md#running-the-tests).

<!-- BEGIN GENERATED CASES: go run ./test/spec -->
33 test cases: 11 unit, 18 integration, 4 e2e.

| Case | Level | Verifies | Location |
|---|---|---|---|
| `TestSSHRejectsBadKeyFiles` | Unit | bxp ssh refuses before asking the CA when the key file is missing, is a private key's file name, does not exist, or is not an SSH public key. (1 sub-case) | [cmd/bxp/client_test.go](../../cmd/bxp/client_test.go) |
| `TestIssueSSHAcceptsCommonKeyTypes` | Unit | Ed25519, RSA 2048 and ECDSA P-256 keys get certificates. (1 sub-case) | [internal/ca/ssh_test.go](../../internal/ca/ssh_test.go) |
| `TestIssueSSHDoesNotShareTemplateExtensions` | Unit | Changing an issued certificate's extensions does not change the built-in profile. | [internal/ca/ssh_test.go](../../internal/ca/ssh_test.go) |
| `TestIssueSSHHost` | Unit | A host certificate is signed by the host CA key, accepted for its host name, and has no extensions. | [internal/ca/ssh_test.go](../../internal/ca/ssh_test.go) |
| `TestIssueSSHProfile` | Unit | A profile's critical options and extensions reach the certificate, and the CA finds the profile by name. | [internal/ca/ssh_test.go](../../internal/ca/ssh_test.go) |
| `TestIssueSSHRejects` | Unit | Requests the profile does not allow are refused, such as no principals or an empty principal. (1 sub-case) | [internal/ca/ssh_test.go](../../internal/ca/ssh_test.go) |
| `TestIssueSSHRejectsBadKeys` | Unit | A 1024-bit RSA key, and an SSH certificate offered as a key, are refused. (1 sub-case) | [internal/ca/ssh_test.go](../../internal/ca/ssh_test.go) |
| `TestIssueSSHUser` | Unit | A user certificate is signed by the user CA key (not the host CA key) and accepted for the principals it lists, not for others. | [internal/ca/ssh_test.go](../../internal/ca/ssh_test.go) |
| `TestSSHTemplateByName` | Unit | The SSH profiles are found by name, and a TLS profile is not found as an SSH one. | [internal/ca/ssh_test.go](../../internal/ca/ssh_test.go) |
| `TestReplacedHostCAKeyIsOwn` | Unit | Host certificates signed with a replaced host key can still be renewed. | [internal/ca/sshca_test.go](../../internal/ca/sshca_test.go) |
| `TestSSHCAReplacement` | Unit | Replacing the SSH user CA key in two steps: the next key is published beside the current one, which still signs; only one next key may wait, and only for that CA; activating without a next key is refused; after activation the new key signs, the old private key is gone, and its public key is kept. | [internal/ca/sshca_test.go](../../internal/ca/sshca_test.go) |
| `TestSSHAgentKeyWithPassphrase` | Integration | A key with a passphrase and no terminal: it says so, before a token is spent. | [cmd/bxp/agent_test.go](../../cmd/bxp/agent_test.go) |
| `TestSSHAgentMissing` | Integration | bxp ssh --agent without a running agent says how to start one (SSH_AUTH_SOCK), and bxp ssh with neither --key nor --agent says what is missing. | [cmd/bxp/agent_test.go](../../cmd/bxp/agent_test.go) |
| `TestSSHAgentOnly` | Integration | --agent without --key: a new key in memory, nothing on disk. | [cmd/bxp/agent_test.go](../../cmd/bxp/agent_test.go) |
| `TestSSHAgentWithKey` | Integration | --agent with --key: the certificate file as always, and the key with its certificate in the agent. | [cmd/bxp/agent_test.go](../../cmd/bxp/agent_test.go) |
| `TestSSHHostWithChosenPrincipalAndValidity` | Integration | bxp ssh with a host token gets a host certificate for the principal and lifetime asked for. | [cmd/bxp/client_test.go](../../cmd/bxp/client_test.go) |
| `TestSSHReplacesAnOldCertificate` | Integration | bxp ssh replaces an existing certificate file for the same key. | [cmd/bxp/client_test.go](../../cmd/bxp/client_test.go) |
| `TestSSHUser` | Integration | bxp ssh writes a user certificate for the key in the file, with the token's principals, next to the key, and says which file and principals. | [cmd/bxp/client_test.go](../../cmd/bxp/client_test.go) |
| `TestTokenSubjectBecomesTheSSHKeyID` | Integration | The subject given to "bxp token" must show up in the key ID of the SSH certificate, all the way through the real server. | [cmd/bxp/client_test.go](../../cmd/bxp/client_test.go) |
| `TestNewSSHHostCA` | Integration | The whole replacement of the SSH host CA key, seen by a host: the new key is published first, then signs; the host renews its old certificate and gets one signed with the new key. | [cmd/bxp/sshca_test.go](../../cmd/bxp/sshca_test.go) |
| `TestSignSSHHost` | Integration | An ssh-host token gets a host certificate signed by the host CA key, for the host name. | [internal/server/ssh_test.go](../../internal/server/ssh_test.go) |
| `TestSignSSHKeyIDIsSubjectAndTokenID` | Integration | The key ID tells an SSH server's log who logged in. It must name the person the token was made for, also when the login name is shared. | [internal/server/ssh_test.go](../../internal/server/ssh_test.go) |
| `TestSignSSHRejectsBadRequests` | Integration | Malformed SSH requests are refused with 400 and a message: no public key, something that is not a key, a 1024-bit RSA key, a certificate sent as a key, and the other cases in the table. (1 sub-case) | [internal/server/ssh_test.go](../../internal/server/ssh_test.go) |
| `TestSignSSHRejectsMissingToken` | Integration | An SSH request without a token is refused with 401. | [internal/server/ssh_test.go](../../internal/server/ssh_test.go) |
| `TestSignSSHRejectsPrincipalsNotInToken` | Integration | Another principal, an extra one, or one in another letter case is refused with 403, and the token still works afterwards. (1 sub-case) | [internal/server/ssh_test.go](../../internal/server/ssh_test.go) |
| `TestSignSSHTokenWorksOnlyOnce` | Integration | A token gets one SSH certificate; a second request with it is refused as already used. | [internal/server/ssh_test.go](../../internal/server/ssh_test.go) |
| `TestSignSSHUser` | Integration | An ssh-user token gets a user certificate for the key sent, signed by the user CA key, with all of the token's principals and a key ID that starts with the token's subject. | [internal/server/ssh_test.go](../../internal/server/ssh_test.go) |
| `TestSignSSHWithFewerPrincipalsAndValidity` | Integration | A request may ask for fewer principals than the token gives and a shorter lifetime; the key ID still names who the token was for. | [internal/server/ssh_test.go](../../internal/server/ssh_test.go) |
| `TestTokensOnlyWorkForTheirOwnKindOfCertificate` | Integration | A token for one kind of certificate must not work for another kind. | [internal/server/ssh_test.go](../../internal/server/ssh_test.go) |
| `TestSSHAgent` | E2E | "bxp ssh --agent" with a real ssh-agent: without --key, a new key and its certificate go into the agent and nothing touches the disk; with --key, the certificate file is written and the agent holds both. | [test/e2e/agent_test.go](../../test/e2e/agent_test.go) |
| `TestOpenSSHLogin` | E2E | OpenSSH: sshd trusts the CA's user key, and presents a host certificate from the CA; ssh logs in with a user certificate, and trusts the host through the line "bxp trust --ssh" wrote. | [test/e2e/consumers_test.go](../../test/e2e/consumers_test.go) |
| `TestSSH` | E2E | SSH user and host certificates, checked with ssh-keygen. (1 sub-case) | [test/e2e/core_test.go](../../test/e2e/core_test.go) |
| `TestNewSSHUserCA` | E2E | A new SSH user CA key, in its two steps, with a real sshd: logins keep working throughout, as long as servers trust both keys during the change; afterwards only the new key's certificates are accepted where only the new key is trusted. | [test/e2e/maintenance_test.go](../../test/e2e/maintenance_test.go) |
<!-- END GENERATED CASES -->
