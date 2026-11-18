# BastionXP CA

[![ci](https://github.com/bastionxp/bastionxp-ca/actions/workflows/ci.yml/badge.svg)](https://github.com/bastionxp/bastionxp-ca/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

The open-source private CA for SSH and TLS certificates: simple,
self-hosted, short-lived certificates. One binary, `bxp`, creates the CA,
runs the server that signs certificates, and requests certificates on the
machines that need them.

**Documentation: <https://docs.bastionxp.com/ca/>**

## Features

- **A complete CA in one command:** a root, an intermediate, and SSH user
  and host CA keys. The root key is encrypted and can live offline.
- **Short-lived certificates, renewed automatically.** Five built-in
  profiles (TLS server, TLS client, device, SSH user, SSH host), plus your
  own: S/MIME, code signing, longer-lived certificates.
- **Several ways to prove who is asking:** one-time tokens, single sign-on
  with your identity provider (OIDC: Entra ID, Okta, Google, Keycloak,
  AD FS), Active Directory or LDAP passwords, ACME (certbot, lego, acme.sh,
  Caddy, cert-manager), and SCEP for phones, managed laptops and network
  gear.
- **Revocation** with a CRL and OCSP, and a list of every certificate
  issued.
- **Operations built in:** reload without restart, `bxp doctor`, backups
  while running, Prometheus metrics, JSON logs, encrypted keys with the
  passphrase from systemd credentials.
- **No dependencies:** a static binary or a container image. Its state is
  one directory with the keys and a SQLite file.

## Install

- **Release archives** for Linux, macOS and Windows are on the
  [releases page](https://github.com/bastionxp/bastionxp-ca/releases), with
  checksums and build provenance.
- **Container image:** `ghcr.io/bastionxp/bastionxp-ca`.
- **From source**, with Go 1.26 or newer: `make build` writes `bin/bxp`.

See [Installation](https://docs.bastionxp.com/ca/getting-started/installation/).

## Quick start

```sh
bxp init --config bastionxp-ca.yaml       # create the CA
bxp serve --config bastionxp-ca.yaml      # run the server

# on any machine
bxp trust --ca-url https://ca.example.com:8443 --fingerprint <root fingerprint>
bxp tls --token <token> --name web.example.com
bxp ssh --token <token> --key ~/.ssh/id_ed25519.pub
```

The [Quick start](https://docs.bastionxp.com/ca/getting-started/quickstart/)
walks through it in ten minutes, with a minimal configuration.

## Documentation

| | |
|---|---|
| [Getting started](https://docs.bastionxp.com/ca/getting-started/) | Install, quick start, and what to set up before real use |
| [Concepts](https://docs.bastionxp.com/ca/concepts/) | The PKI hierarchy, verifiers, the certificate lifecycle, the security model |
| [Server](https://docs.bastionxp.com/ca/server/) | Run, configure, protect, monitor, back up and upgrade the CA |
| [Client](https://docs.bastionxp.com/ca/client/) | Trust the CA; get, use and renew TLS and SSH certificates |
| [Authentication & protocols](https://docs.bastionxp.com/ca/protocols/) | Tokens, OIDC, LDAP, ACME, SCEP, and the access rules |
| [Reference](https://docs.bastionxp.com/ca/reference/) | Every command, configuration key, API endpoint, metric and log message |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/architecture.md](docs/architecture.md).
The [test specification](docs/testing/README.md) describes how BastionXP CA
is tested, from unit tests to end-to-end tests of the real binary with
certbot, lego, OpenSSH and others, with every test case by feature.

## Security

Report security problems privately, not in a public issue: see
[SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

The license covers the code, not the BastionXP names and logos. See
[TRADEMARKS.md](TRADEMARKS.md) for how you may use them.
