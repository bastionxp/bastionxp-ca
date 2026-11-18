# Contributing to BastionXP CA

Thanks for helping. This project aims to stay small and easy to read, so a
new contributor can understand any package in one sitting.

## Getting started

```sh
make build   # builds bin/bxp
make build-linux   # static Linux binaries: bin/linux_amd64/bxp, bin/linux_arm64/bxp
make test    # runs all tests
make test-e2e   # the real binary against openssl, ssh-keygen, certbot, lego, acme.sh, scepclient (see test/e2e/README.md)
make test-container   # the container image: init, serve, a certificate from this machine (needs Docker)
make lint    # go vet, gofmt, copyright headers, and the test specification
make spec    # rewrite the test specification's case tables after adding tests
make test-samba   # LDAP tests against a real Samba AD domain controller (needs Docker)
make test-keycloak   # OIDC login tests against a real Keycloak (needs Docker)
make fuzz    # fuzz every parser of untrusted input, 30s each (FUZZTIME=5m for longer)
```

**Fuzzing.** Code that reads what anybody can send (ACME, SCEP, OCSP,
CSRs, tokens, renewal proofs) or what ends up in an LDAP filter has a
`Fuzz` test next to it. Add one when you add such code, with an invariant
beyond "does not crash" where there is one (a forged token is never
accepted, a username never changes the LDAP filter). A failing input that
`go test -fuzz` saves under `testdata/fuzz/` is a regression test: commit
it with the fix. CI fuzzes every target for 5 minutes once a week.

Read [docs/architecture.md](docs/architecture.md) first. It is short.

## Contributor License Agreement

Before we can merge your first pull request, you need to sign a
Contributor License Agreement (CLA). You sign once, and it covers all your
future contributions. You keep the copyright in your work. The CLA gives
Ampas Labs Inc., which runs this project, the rights it needs to
distribute your contribution and to license the project in the future.

- **Contributing for yourself:** sign the
  [Individual CLA](docs/cla/icla.md). A bot comments on your first pull
  request with a link; signing takes one click with your GitHub account.
- **Contributing as part of your job:** your employer probably owns what
  you write at work. Ask them to sign the
  [Corporate CLA](docs/cla/ccla.md) and list you as an authorized
  contributor, and sign the Individual CLA yourself as well.

## Rules of the house

**Keep it simple.**
- Prefer the standard library. Adding a dependency needs a good reason,
  stated in the pull request. A CA is security software, and every
  dependency is code our users have to trust.
- No global variables for state or configuration. Pass what a function
  needs as arguments.
- Prefer a little repetition over a clever abstraction.
- One pull request does one thing.

**Start every file with the copyright header.** Go files, Dockerfiles,
the Makefile and GitHub workflows begin with these two lines (`#` instead
of `//` outside Go), then a blank line:

```go
// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0
```

Use the year you create the file, and leave it alone afterwards.
`make lint` fails on a file without it.

**Write for the next reader.**
- Every package has a doc comment that says what it is for.
- Comments explain *why*, not *what*.
- Error messages say what went wrong and, if possible, what to do about it.

**Test what you add.** The [test specification](docs/testing/README.md)
explains the test levels, how to run them, and how to add a test.
- New behaviour needs a test. A bug fix needs a test that fails without the fix.
- For anything that rejects bad input, test the rejection too.
- Tests use the standard `testing` package and temporary directories
  (`t.TempDir()`). They must not need the network.

**Words we use.**
- A **verifier** checks who is asking for a certificate (one-time token,
  identity provider login, ACME, SCEP). Use this word in code, configuration and docs.
- A **profile** describes a kind of certificate (`tls-server`, `ssh-user`...).

## Security issues

Please do not open a public issue for a security problem. Report it
privately through GitHub's "Report a vulnerability" button on the
repository's Security tab.
