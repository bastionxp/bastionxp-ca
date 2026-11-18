# End-to-end tests

Part of the [test specification](../../docs/testing/README.md), which
lists every case by feature.

These tests build the real `bxp` binary and use it the way people do. Each
test creates a CA with `bxp init`, starts `bxp serve` as its own process,
and gets certificates from it with `bxp` and with other programs. Every
certificate is then checked by a program other than BastionXP CA.

```sh
make test-e2e
```

The first run downloads the ACME and SCEP clients into `.tools/` (ignored
by git), at the versions pinned at the top of the `Makefile`. Later runs
reuse them. The whole suite takes about 20 seconds.

## Where it runs

| Where | What |
|---|---|
| Linux (CI, every push) | the whole suite, with every tool required (`BXP_E2E_REQUIRE_ALL=1`) |
| macOS and Windows (CI) | `TestSmoke`: a CA, its server, and the main client commands, checked with Go itself, beside the unit tests. On every push once the repository is public; by hand before that |
| your machine | `make test-e2e`; tests whose tools are missing are skipped and say why |

The CA server is hosted on Linux, so the tests that need signals (stop,
reload), real ACME and SCEP clients, sshd or openssl run there and on
macOS. Windows runs only `TestSmoke`.

Next to this suite, CI also checks the systemd units
(`systemd-analyze verify`), the container image (`make test-container`, also
before every release), and, weekly, the logins against Keycloak and Samba
(`.github/workflows/integrations.yml`).

## What is tested

| Test | What it does | Checked with |
|---|---|---|
| `TestSmoke` | on every system, Windows included: `init`, `serve`, `trust`, `token`, `tls` (names from the token), `ssh`, `renew`, `list`, `revoke`, `doctor` | Go's `crypto/x509` and `x/crypto/ssh` |
| `TestCommandLine` | `--version`, an unknown command, a second `init` failing before any question, `fingerprint`, `trust` refusing a wrong fingerprint | exit codes, `openssl x509 -fingerprint` |
| `TestTLSAndRevocation` | `trust`, `token`, `tls`; a token used twice; `revoke`; OCSP and CRL | `openssl verify`, `openssl ocsp`, `openssl crl -verify` |
| `TestSSH` | user and host certificates with `bxp ssh` | `ssh-keygen -L` |
| `TestRenew` | `renew` with nothing to do, `--force`, `--exec`; no renewal once revoked | `openssl verify` |
| `TestServerLifecycle` | reload on SIGHUP, a broken configuration ignored, a clean stop on SIGTERM, data kept across a restart | the server log, `list certificates` |
| `TestACMEClients` | `bxp acme`, certbot, lego and acme.sh each issue (http-01), renew and revoke a certificate; certbot revokes with the certificate's own key and unregisters. ACME Renewal Information: after `bxp revoke`, a plain `certbot renew` and `bxp acme renew` (no force) replace the certificate; lego and acme.sh send `replaces`. Then `bxp list acme-orders` and `acme-accounts` | `openssl verify`, `bxp list certificates --revoked`, `bxp list acme-orders` |
| `TestConcurrentProcesses` | 150 issuances, 16 at a time, each `bxp token` + `bxp tls`, while `bxp revoke`, `bxp list` and `bxp backup` run in loops on the same database | no failed process, no "database is locked", every certificate and revocation recorded, every backup opens |
| `TestNoSecretsInLogs` | tokens (TLS, SSH, SCEP, reused, forged), renewal and revocation, with encrypted keys and `--log-format json --log-level debug` | every log line is JSON; no token, token signature, passphrase or private key in the log or in any client output |
| `TestOpenSSHLogin` | a real `sshd` trusting the CA's user key and showing a host certificate | `ssh` logs in with a user certificate, trusting the host through `bxp trust --ssh`; refused for another principal, without a certificate, and without the `known_hosts` line |
| `TestTLSHandshake` | `openssl s_server` with a `bxp` certificate; mutual TLS | `openssl s_client` and `curl` (and the wrong name refused); mutual TLS with `openssl` and Go's `crypto/tls`: a `tls-client` certificate gets in, none or a `tls-server` one does not |
| `TestEncryptedServerKeys` | `init` with encrypted server keys; `serve` with the passphrase from `ca.key_passphrase_file`, a systemd credential, `BXP_KEY_PASSPHRASE_FILE`, `BXP_KEY_PASSPHRASE` | it starts and issues; a wrong or missing passphrase stops it at once with a clear error, and the passphrase never appears |
| `TestNewIntermediate` | the root key moved offline, `new-intermediate --root-key`, a restart | new certificates come from the new intermediate; old ones still verify; renewing an old one moves it to the new intermediate |
| `TestExternalRoot` | `init --external-root`; openssl plays a company root and issuing CA and signs the CSR; `new-intermediate --import` | `root.crt` is the company root; a certificate verifies against it from the chain as delivered |
| `TestNewSSHUserCA` | `new-ssh-ca user`, then `--activate`, with a real sshd | logins keep working while servers trust both keys; afterwards the old key's certificates are refused where only the new key is trusted |
| `TestBackupAndRestore` | `bxp backup` while serving, then a restore in place of the data directory | the backup is private; certificates and revocations from before the backup are there, later ones are not; the CA issues again |
| `TestReloadApplies` | SIGHUP after adding an ACME domain, and after a restart-only change | the new domain gets a certificate without a restart; the restart-only change is reported and the server goes on |
| `TestSSHAgent` | `bxp ssh --agent` with a real ssh-agent, with and without `--key` | the certificate is in the agent (`ssh-add -L`); without `--key` nothing is written to disk |
| `TestSSHHostRenew` | `bxp renew` on an SSH host certificate | a new certificate, same host key, kind and principals |
| `TestACMEOtherChallenges` | tls-alpn-01 on port 443 with `bxp acme` and lego; an IP address (RFC 8738) with lego; a wildcard with dns-01, lego's exec hook writing the TXT record into a small DNS server the CA asks (`acme.dns_resolver`); an IP outside `allowed_ip_ranges` | `openssl verify`, the certificate's names |
| `TestACMERateLimits` | `orders_per_account_per_hour` and `accounts_per_ip_per_hour` with `bxp acme` | refused at once with the CA's reason and when to try again, not after a silent wait |
| `TestAutocert` | a Go web server with `golang.org/x/crypto/acme/autocert` gets its certificate during the first TLS handshake (tls-alpn-01); restarted, it uses its cache | `curl` gets the page; `openssl verify` of the cached certificate; one order only, after the restart too |
| `TestCaddy` | Caddy, configured with BastionXP CA as its ACME server, gets certificates for two sites: one proved with http-01, one with tls-alpn-01 | `curl` gets each site's page; `openssl verify` of the certificates Caddy stored; `bxp list acme-orders` shows the challenge used |
| `TestTokenLimits` | an expired token; names, extra names and an SSH principal the token does not give; a TLS token for SSH | each refused with its reason; a refused request does not use the token up |
| `TestSCEPStaticChallenge`, `TestSCEPStaticLimit`, `TestSCEPGetCert` | the shared challenge with scepclient; `dns_domains`; a wrong challenge; `max_per_hour`; `bxp scep getcert` | the refusal reason in the server's log; getcert returns exactly the issued certificate |
| `TestGracefulStopUnderLoad` | SIGTERM while 60 requests run | clean exit; requests in flight complete, the others fail with a message; every certificate a client got is listed; `doctor` finds the database intact |
| `TestMetrics` | `/metrics` with `token_file` | 401 without the token; issued and refused counters move |
| `TestDoctorFindsProblems` | the server not running, a key readable by others, a missing file | a warning, a warning, a failure with exit status 1 |
| `TestClientErrors` | nothing at the address, a server of another CA, `bxp trust` for another CA, the CA down | a message that says which, a non-zero exit, no crash; the token is not spent |
| `TestSCEPClients` | `bxp scep` (enroll, renew) and micromdm's scepclient, with a token as the challenge | `openssl verify` |

## What it needs

- **Go and Python 3**, to install the clients.
- **openssl, curl, ssh-keygen, ssh and sshd**, from the system. On Linux,
  `sshd` is in the `openssh-server` package, and wants `/run/sshd` to
  exist: `sudo mkdir -p /run/sshd`.
- **socat**, for acme.sh's standalone mode: `brew install socat` or
  `apt-get install socat`.
- **Ports 80 and 443**, where the ACME clients answer the CA's http-01
  and tls-alpn-01 checks. macOS allows that without root. On Linux, once:
  `sudo sysctl -w net.ipv4.ip_unprivileged_port_start=80`.
- **Names ending in `.localhost` resolve to this machine.** macOS and
  Linux with systemd-resolved do this already. CI checks it before the
  tests and stops if not. If one name fails on macOS ("no such host") while
  others work, its DNS cache holds a stale answer:
  `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`.

Without a tool, the tests that need it are skipped and say why. With
`BXP_E2E_REQUIRE_ALL=1`, as in CI, they fail instead.

The tests run on Linux and macOS, not Windows: they stop and reload the
server with Unix signals.

## Things to know

- **A revocation takes up to 5 seconds to show.** `bxp revoke` writes to
  the database and the running server notices within 5 seconds, as
  documented. `TestTLSAndRevocation` waits for the server's
  `certificate revoked` log line before it asks OCSP.
- **scepclient talks to the CA through a local HTTP proxy.** It cannot be
  told which root to trust, and Go programs on macOS ignore
  `SSL_CERT_FILE`. The proxy handles only TLS: the SCEP messages, their
  signatures, encryption and the challenge reach the CA unchanged.
- **Nothing outside the test's temporary directories is touched.** `HOME`
  and `BXP_CLIENT_DIR` point into them, so `bxp trust` and the clients
  never write to your own configuration.
- **To update a client,** change its version in the `Makefile`. The next
  run installs it; CI's cache key changes with the `Makefile`. The
  client's page on the documentation site names the tested version:
  update it there too.
- **certbot and lego wait a random time before renewing** when no one is
  at a terminal. The tests skip that with `--no-random-sleep-on-renew` and
  `--no-random-sleep`.
