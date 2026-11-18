# Architecture

BastionXP CA is one certificate authority (CA) in one binary.

## The CA

```
Root CA  (trust anchor, key kept offline)
   │ signs
   ▼
Intermediate CA ──signs──▶ TLS server and client certificates

SSH user CA key ──signs──▶ SSH user certificates
SSH host CA key ──signs──▶ SSH host certificates
```

There is exactly one of each. `bxp init` creates them and stores them as
files in the data directory. The root is valid for 10 years and the
intermediate for 3 by default (`ca.root_validity`,
`ca.intermediate_validity`); a replacement intermediate may never outlive
the root. The root private key is only used during
`init`; the running server never reads it.

## How a certificate is issued

Every certificate, whatever way it is requested, goes through the same steps:

```
request ──▶ verifier ──▶ policy ──▶ profile ──▶ CA signs ──▶ stored + audit log
            who are      may they     what kind
            you?         have this    of cert?
                         name?
```

- A **verifier** checks who is asking: a one-time token, a login with the
  identity provider or a directory password, an ACME challenge, a SCEP
  challenge.
- The **policy** of that verifier says which names it may hand out.
- A **profile** fixes the technical details of a certificate kind: key
  usage, default and maximum lifetime.
- The **CA** signs. It has two entry points, `IssueX509` and `IssueSSH`,
  and nothing else signs certificates.

The verifiers are one-time tokens, a login with the identity provider
(OIDC), a login with a directory password (LDAP), ACME and SCEP.
Each has a section below. Every issued certificate is written to the
server's log and recorded in the database.

## One-time tokens

The token verifier is the simplest one, and the others follow its shape.

```
admin:   bxp token --name web.example.com ──▶ token (a signed JWT)
client:  bxp tls --token ...
         = POST /v1/x509/sign  with the token and a CSR
server:  1. token signature and expiry ok?      (internal/token)
         2. names in the CSR all in the token?  (internal/policy)
         3. token not used before? record it    (internal/store)
         4. sign                                (internal/ca)
```

- A token is a JWT signed with `token.key` in the data directory (ECDSA
  P-256, ES256). It carries the profile, the allowed names, a subject
  (who the token was made for), an expiry time and a random ID.
- Tokens are created on the CA machine by reading `token.key` directly,
  or by the CA itself for someone who has logged in (below).
- "One-time" is enforced by the database: the token ID is inserted into a
  table with a unique key, so of two requests with the same token only one
  can win, also across restarts.
- The token is marked as used right before signing, not after. A request
  that fails earlier (wrong names, bad CSR) leaves the token usable.

SSH certificates work the same way through `POST /v1/ssh/sign`, with an
SSH public key instead of a CSR. Two things differ:

- The names in the token are the principals (login names or host names).
  They are compared exactly, including upper and lower case.
- The certificate's key ID is `<subject>-<token ID>`, both taken from
  the token. SSH servers log the key ID at each login: the subject says
  who logged in, and the token ID matches the login to one line in the
  CA's log. The requester cannot choose it.

A token only works at the endpoint for its kind of certificate: a
`tls-server` token cannot get an SSH certificate.

## Login with the identity provider

The login verifier does not sign anything itself. It turns "this person
logged in with the company's identity provider" into a one-time token, and
the token takes the same road as every other token. A login is one trip of
the person's browser:

```
bxp ssh --key ...          listens on 127.0.0.1:<port>
  │ opens the browser at
  ▼
CA   GET /v1/oidc/login               signs "what was asked for"
  │ redirect
  ▼
the identity provider                 the person logs in
  │ redirect
  ▼
CA   GET /v1/oidc/callback            who is it? may they have it?
  │ redirect, with a one-time token
  ▼
http://127.0.0.1:<port>/callback      the command takes the token
  │
  ▼
CA   POST /v1/ssh/sign  (token)       the certificate, as before
```

`internal/oidc` speaks OpenID Connect, so one implementation serves Entra
ID, AD FS, Google, Okta, Keycloak and the others. The flow is in
`server/login.go`. It is tested against a fake provider that can also misbehave
(`internal/oidc/oidctest`), and end to end against a real Keycloak in
Docker (`make test-keycloak`).

- **Who are you?** The CA exchanges the provider's code itself, with its
  own client ID and secret, and checks the ID token: the signature against
  the provider's published keys, the issuer, the audience (our client ID),
  the expiry, and the nonce. The code is protected with PKCE. Nothing from
  the provider ever reaches the person's machine. A name taken from the
  `email` claim counts only if the provider says it verified it. A person
  in more groups than the token can carry (Entra ID) is refused, not
  treated as a member of none.
- **What may you have?** `internal/policy` decides in the callback, from
  the `access` rules ("these users or groups get these principals, or
  admin"). A person may have, for themselves, an SSH certificate of the
  verifier's `ssh.cert_profile` with their own principals, and a TLS
  certificate of its `x509.cert_profile` for their own name, which the CA
  decides (`policy.Own`); the token's subject is then always their name.
  Everything else needs an admin. A login that names no profile asks for
  one of these by kind (`ssh`, `x509`), and the server fills in the
  verifier's profile before the login starts.
  Groups are read at every login, so a change at the provider takes effect
  at the next certificate, with nothing synced. The rules are plain data:
  an enterprise edition can feed them, or the groups, from somewhere else
  without changing this code.
- **Nothing is stored.** While the person is at the provider, the CA has to
  remember where to send them and what they asked for. It signs that (a
  "login", in `internal/token`) and passes it through the provider as the
  OAuth `state`. The nonce and the PKCE verifier are derived from the
  login's ID with a key derived from the token key, so the verifier never
  travels through the browser. There are no cookies, no sessions and no
  table of logins. Nothing is saved on the person's machine either, so
  there is nothing to steal between two requests and nothing to revoke:
  whether someone may still log in is checked at every login.
- **Who created a token** (`created_by`) and **who it is for** (`subject`)
  are separate fields, both written to the log. When an admin gets a token
  for a host, the certificate is the host's, and the log says the admin
  authorised it.

Four things keep the token with the person who logged in. Each has tests
that try to get around it:

1. **The result only goes to `http://127.0.0.1:<port>`.** The CA refuses
   every other callback address before the trip to the provider starts. Without
   this, a link to the real CA could deliver a person's token to somebody
   else's server after an honest login. `127.0.0.1` always means "the
   machine the browser runs on", so a link sent to a victim delivers the
   token to the victim's own machine, where nobody is listening.
2. **The callback address cannot be changed on the way.** It is inside the
   signed login. The callback endpoint accepts only logins this CA signed.
3. **The command only takes its own reply.** It puts a random value in the
   login and ignores any reply without it. So a web page cannot push
   somebody else's token into a waiting command.
4. **The token is tied to the key.** The command sends the fingerprint of
   its public key, the CA writes it into the token, and the sign endpoints
   refuse any other key. Such a token also lives for one minute only. A
   token that leaks from the browser's address bar or history is of no use
   to anybody without the private key.

Signed logins and one-time tokens are JWTs signed with the same key. A
field in them (the audience) says which of the two a JWT is, and each
endpoint accepts only its own kind.

Limits to know:

- **The browser must trust the CA**, because it visits the CA's address.
  Install `root.crt` on the machines people log in from.
- **No browser, no login.** Machines without one use one-time tokens.
- Rules by name match the name the provider reports. If the provider
  lets a name be given to someone else after a person leaves, remove
  people from the rules when they leave, or use rules by group.
- Tokens that admins get with `bxp token` from their own machine are meant to be
  handed on, so they are not tied to a key, and they pass through the
  browser's address bar on the admin's machine.

## Login with a directory password (LDAP)

For companies with Active Directory and no identity provider. The
command sends the username and password to `POST /v1/ldap/login`; the CA
checks them with the directory and answers with a one-time token, made by
the same code as after a browser login (`tokenFor` in `server/login.go`):
the same `access` rules, the same key-bound, one-minute token, the same
log line. The handler is `server/ldap_login.go`, the directory client
`internal/ldap`.

A login is four steps on one TLS connection (LDAPS or StartTLS, the
directory's certificate checked):

1. Bind as the CA's service account.
2. Search the person's entry: the configured filter, with what they typed
   escaped. Exactly one entry must match; AD-disabled accounts are
   refused.
3. Bind as that entry with the password. The directory decides.
4. Bind as the service account again and read the groups below
   `group_base_dn` (AD's "in chain" rule, so nested groups count). Each
   group is given to the rules by its common name and by its full DN.

What makes or breaks it, each with tests against a fake AD
(`internal/ldap/ldaptest`) that answers like Windows Server AD, and again
against a real Samba AD domain controller in Docker (`make test-samba`):

- **No empty password ever reaches the directory.** AD treats a bind with
  a name and an empty password as an anonymous bind and answers
  "success"; a client that relied on that answer would let anybody in as
  anybody.
- **No filter injection.** `*`, `(`, `)` and `\` in a username are escaped.
- **No lockout by proxy.** Directories lock an account after a few wrong
  passwords. The CA counts failures per username (3) and per address
  (20) in 15 minutes and stops passing logins on when either is reached,
  so it cannot be used to lock people out of their company account. The
  counts are in memory and a restart forgets them.
- **A broken service account is not a wrong password.** It gives `502`,
  is logged as an error, and does not count against the person.

The password passes through the CA. It is never stored or logged, and is
only sent over TLS. That, and no MFA, is why OIDC is the better choice
where there is an identity provider. AD FS speaks OIDC.

## ACME

ACME (RFC 8555) is a verifier where the requester proves something by
itself, with no administrator and no login: that it controls a host name.

```
client                                   CA  (internal/acme)
  new-account  (a public key)       ──▶  remembers the key
  new-order    (host names)         ──▶  policy: are the names in an
                                         allowed domain? one authorization
                                         with a random token per name
  puts the key authorization,
  "<token>.<key fingerprint>", where
  one challenge looks for it
  "ready" (for one challenge)       ──▶  looks: port 80, port 443 or DNS.
                                         Right answer: the name is proved
  finalize     (a CSR)              ──▶  policy: exactly the proved names?
                                         then the CA signs, as always
  downloads the certificate
```

- **Who are you?** The holder of an account key. Every request is signed
  with it (a JWS), names the address it is meant for, and carries a nonce
  that works once, so a recorded request cannot be sent again or sent
  somewhere else. `jws.go` does these checks in one place, for all
  endpoints.
- **Proof.** Three challenges (`challenges.go`), each offered for every
  name; the client answers one:
  - `http-01`: the key authorization at
    `http://<name>/.well-known/acme-challenge/<token>`. Redirects are not
    followed.
  - `tls-alpn-01` (RFC 8737): a TLS connection to `<name>:443` asking for
    `acme-tls/1`; the certificate must name exactly `<name>` and carry
    the SHA-256 of the key authorization in a critical `acmeIdentifier`
    extension.
  - `dns-01`: the SHA-256 of the key authorization in the TXT record
    `_acme-challenge.<name>`, looked up with this machine's resolvers or
    directly at `acme.dns_resolver`.

  The key authorization contains the fingerprint of the account key, so a
  proof counts for that account only. A wildcard (`*.example.com`) is
  offered `dns-01` alone, at `_acme-challenge.example.com`. Which
  challenge decided an authorization is stored with it.
- **Policy** is applied twice. A name must be in one of the
  `acme.allowed_domains`, checked before any request leaves the CA. And
  the CSR must contain exactly the names of the order: not fewer, and above
  all not more.
  Its key must not be the key of any ACME account (RFC 8555, section
  11.1). It may be the key of an earlier certificate: a renewal is just a
  new order, and the RFC sets no rule on keeping the key.
- **Checked at once**, right when the client says "ready", so the answer
  to that request already carries the verdict. A failed proof stays
  failed; the client places a new order.
- **Limits** (`limits.go`), in memory: new accounts per IP address, new
  orders per account, per hour; `429` with `Retry-After` beyond them. No
  External Account Binding.
- **Kept apart.** Orders, authorizations and certificates can only be seen
  and used by the account that created them.
- **Storage.** Accounts, orders and authorizations are in the database
  (`store/acme.go`). Nonces are in memory: after a restart a client gets a
  "bad nonce" answer with a fresh one and repeats its request, which every
  ACME client does by itself.

IP addresses (RFC 8738) are identifiers of type `ip`, allowed within
`acme.allowed_ip_ranges`, proved with `http-01` or `tls-alpn-01` (asking
for the reverse DNS name, with the address in the certificate). An
account's key can be changed (`account.go`, RFC 8555 7.3.5): the request
is signed with the old key and carries one signed with the new key. An
account can be closed (7.3.6): it is marked `deactivated`, and every
request signed by it, a new-account request with its key included, is
refused from then on.

A client can revoke (`revoke.go`, 7.6). The request carries the whole
certificate, which must be the one in the CA's list under that serial
(a forged certificate with a real serial is refused), and is signed
either by the account whose order got it (each order keeps the serial of
its certificate) or with the certificate's own key, as a `jwk`. The
revocation goes into the same list as `bxp revoke`, so the CRL and
OCSP show it at once.

Renewal information (`ari.go`, RFC 9773): an unsigned
`GET /acme/renewal-info/<certID>` answers with a window, two thirds to
five sixths of the lifetime, or "now" (an hour back to now) for a
revoked certificate or one from a replaced intermediate. The certificate
is found by its serial in the CA's list and must have the authority key
ID the client named. A new order may carry `replaces`: accepted from the
account whose order got that certificate, for an order sharing a name,
and refused with `409 alreadyReplaced` when another order that has not
failed or expired already replaces it; the check runs in the same
transaction that creates the order. An order that got a certificate
stays in the database while the certificate is valid, because it says
which account may revoke or replace it.

Not there: External Account Binding and changing contacts.

The server is tested with the ACME client from `golang.org/x/crypto`,
which was written against the RFC by other people (also for the
tls-alpn-01 certificates and dns-01 records), against a small real DNS
server for `acme.dns_resolver`, and by hand with certbot.

## SCEP

SCEP (RFC 8894) is how devices that cannot do anything else get a
certificate. In BastionXP CA it is not a verifier of its own: it is another way
to deliver a one-time token and a CSR. The token travels as SCEP's
"challenge password".

```
device                                    CA
  GetCACert                          ──▶  the RA certificate and the CA's
  CSR with the token as challenge,
  encrypted for the RA, signed with
  the device's new key               ──▶  internal/scep: unpack, check that
                                          the message is signed with the
                                          key in the CSR
                                          internal/server: the same road as
                                          POST /v1/x509/sign: token, policy,
                                          one-time check, CA
  the certificate, encrypted for     ◀──  internal/scep: pack the answer
  the device, signed by the RA
```

- **Two packages, two jobs.** `internal/scep` only speaks the protocol. It
  is handed one function, `IssueFunc`, and knows nothing about tokens or
  policy. That function is `issueForSCEP` in `internal/server`, which calls
  the same `issueX509` as the JSON API. So every rule for tokens (names,
  one-time, tied to a key) holds for SCEP without being written twice.
- **The RA.** SCEP messages are encrypted, and with SCEP that needs an RSA
  key. The CA's keys are ECDSA by default and should not decrypt anything
  anyway. So the SCEP server has its own RSA key with a certificate from
  the CA, the RA ("registration authority"). It is created at the first
  start and replaced when it has 30 days left. It is not a CA certificate:
  it cannot sign certificates.
- **The shared challenge** (`server/scep_static.go`), for device
  management systems that cannot fetch a token per device, is off by
  default. Whoever learns it can enroll, so it is fenced in: one profile,
  names only in configured domains, no IP addresses or URIs, a limit per
  hour for the whole CA, compared in constant time, logged as
  `scep_static`. A challenge that is not the password is checked as a
  token, as before.
- **Refusals** are normal SCEP answers that say "failure". SCEP has only a
  few failure codes and none says much, so the real reason goes to the
  CA's log, with the transaction ID of the request.

The PKCS#7 format of the messages comes from a library
(`go.mozilla.org/pkcs7`); the standard library has none. It encrypts
with DES unless told otherwise, so `scep.go` sets it to AES-256 once.

Every TLS certificate is recorded with how it was obtained (`protocol`:
`api`, `acme` or `scep`; renewals keep it). A certificate is renewed only
that way: `handleRenewX509` takes only `api` certificates, SCEP renewal
only `scep` ones, and ACME clients renew with a new order.

Renewal (RenewalReq) is signed with the device's current certificate and
key, and carries a CSR for the new certificate's key: a new one, or the
current one, which RFC 8894 allows and many devices do (unlike
`bxp renew`, which requires a new key). The server checks it by the rules of
the renewal API (`renewForSCEP`, sharing `renewableRecord` and
`renewX509` with `handleRenewX509`): a valid certificate of this CA, in
the list and not revoked; the new certificate gets its names and profile.
GetCert hands out a certificate from the list by issuer and serial, but
only to a request signed with that certificate's key.

Not there: GetCRL (the CRL is at `/crl`) and polling. The server is tested with its own client, and by hand
with micromdm's `scepclient` (enrollment and renewal) and with a second
independent SCEP client, which builds its messages with different code.

## The list of certificates, and revocation

```
CA.IssueX509 / CA.IssueSSH ──▶ recorded in the database, or not issued

bxp revoke <serial>     ──▶ marks the record as revoked

GET  /crl                  ──▶ all revoked, unexpired certificates, signed
POST /ocsp                 ──▶ good / revoked / unknown for one, signed
```

- **Recorded where it is signed.** The CA is given a recorder
  (`ca.Recorder`, implemented by the store) and calls it for every
  certificate, in the two functions that sign. So no way of requesting a
  certificate can forget to record it, and the server's own certificates
  are in the list too. If recording fails, the certificate is not handed
  out: the CA must not issue what it cannot revoke.
- **Revoking is a local action.** `bxp revoke` runs on the CA machine
  and writes to the database, like `bxp token` reads the token key.
  There is no network endpoint that revokes. The server reads the database
  for every CRL and OCSP request, so it needs no restart and there is no
  cache that could be stale.
- **OCSP says "unknown" for what is not in the list.** Not "good": a
  certificate that claims to be this CA's, but was never recorded, must not
  pass just because nobody revoked it. A request must also name this CA as
  the issuer; a matching serial number alone gets "unknown".
- **Signed by the intermediate.** The CRL and the OCSP answers are signed
  with the key that signs the certificates (`ca/revocation.go`), so a
  client needs nothing but the CA's certificates to check them. The key
  still never leaves the `ca` package.
- **A plain HTTP address, on purpose.** Certificates name where to ask
  (`server.public_url`). Programs that check revocation often cannot use
  HTTPS for it, and need not: everything is signed. So the server can
  listen a second time, with plain HTTP, and serve only its public
  information there (`server/public.go`). A test makes sure that nothing
  that issues certificates is reachable on that address.

SSH certificates can be revoked too, but that only stops their renewal.
SSH servers never ask a CA about certificates; telling them would mean
pushing an OpenSSH revocation list (KRL) to every server, which BastionXP CA
leaves to configuration management for now.

Not there: a KRL for SSH, revocation of the intermediate certificate (that
takes the offline root key), and delegated OCSP signing certificates.

## Renewal

A certificate of this CA, together with its key, is the proof for the next
one. So machines renew without a token and without anybody's help.

```
bxp renew (hourly)      ──▶ nothing while > 1/3 of the lifetime is left
                           ──▶ POST /v1/x509/renew   CSR for a new key
                               POST /v1/ssh/renew    (same host key)
                               Authorization: Bearer <proof>
                               proof: JWT signed with the current key,
                                      current certificate in its header
```

The server (`server/renew.go`) checks, in this order:

1. The certificate in the proof chains to this CA and has not expired
   (for SSH: signed by the host CA, a host certificate, not expired).
2. The proof is signed with that certificate's key. Having a copy of the
   certificate, which is public, is not enough.
3. The proof is meant for this kind of renewal, expires within 5 minutes,
   and covers exactly this request's body (`body_sha256`).
4. The certificate is in the list, is exactly the recorded one, and is not
   revoked.
5. The proof's ID has not been used before. It goes into the same table as
   one-time tokens, so a captured request cannot be sent again.

The new certificate gets the old one's names, profile and lifetime, never
anything more; adding names takes a token. A TLS renewal must use a new
key; the client makes it of the same type and size as the old one, so a
renewal never changes what the programs using the certificate must
support. An SSH host renewal keeps the host key, which is what clients
know.

Only SSH host certificates are renewed, not user certificates. A user
certificate lasts hours and stands for a person; letting it renew itself
would turn a short-lived login into one that never ends. People log in
again with `bxp ssh`.

Why a signed request and not a TLS client certificate: it works through
proxies that end TLS, it never makes a browser offer a certificate on the
other pages of the CA, and the same mechanism covers SSH, whose
certificates are not TLS certificates. Renewal stops at expiry and at
revocation, so a stolen key cannot be renewed forever.

## The client

`bxp tls` and `bxp ssh` are the other end of the API, and so is
`bxp token` when it runs away from the CA machine.
`bxp acme` is a small ACME client built on
`golang.org/x/crypto/acme` (issue, renew, revoke, rollover-key,
deactivate; with `--directory`, against any ACME CA), and `bxp scep` (enroll, renew, getcert) uses the client in
`internal/scep`.
They live in the same binary as the server, so there is one thing to
install, but they use nothing from the server side: no configuration file
and no data directory, only the server's address, `root.crt`, and a token
or a browser to log in with.

- **Trust comes first.** `bxp trust` fetches the root, accepts it only
  if its SHA-256 fingerprint is the one the person was given by the
  administrator, then connects again trusting only that root, so a server
  that merely hands out a copy of the public root is refused. It saves the
  address and the root for the other commands; flags and environment
  variables still win. There is deliberately no endpoint that serves the
  fingerprint: one fetched from the CA would prove nothing.
- `internal/api` holds the JSON message types. The server and the client
  both import it, so they cannot drift apart.
- `internal/client` sends the requests. It only talks HTTPS and only to a
  server whose certificate comes from the given root, so a token is never
  sent to a server that is not the CA.
- Private keys are created on the requesting machine and never sent.

## The database

One SQLite file, `bastionxp-ca.db`, opened by one connection. It carries a
schema version (SQLite's `user_version`): at each start, `store.Open`
applies the migrations the file has not had yet, each in a transaction
with the version change, and refuses a file from a newer version. A schema
change is a new migration at the end of the list; released ones are never
edited. The commands that only look (`doctor`, the `list` commands,
`backup`) use `store.OpenReadOnly` instead: it never migrates, and
`CheckVersion` tells them whether the file has this version's schema. So a
newer binary run to look before an upgrade cannot update the database
under the older server that still runs. `bxp backup` copies the file
with `VACUUM INTO`, a consistent snapshot that is safe while the server
writes, and of the schema the file has.

## Caching revocation answers

The CRL and OCSP endpoints are public, and signing costs CPU, so the
server reuses signed answers for up to 5 minutes (`server/revcache.go`).
Revocations are written to the database by `bxp revoke`, outside the
server, so a watcher reads a cheap summary of the revocations every 5
seconds; when it changes, the cached answers are dropped and each new
revocation is logged as `certificate revoked`. Caching is on only while
the watcher runs. The OCSP cache is bounded, so questions about made-up
serial numbers cannot fill the memory.

## The CA's keys

There is exactly one root and one intermediate, both made by `init`.
`serve` never reads the root key, so it can live offline from the start
(`init --root-key-out`).

`bxp new-intermediate` replaces the intermediate in place
(`ca.ReplaceIntermediate`): a new key and certificate signed by the root,
the old key removed, the old certificate kept in `data_dir/replaced` and
never loaded. The server still loads exactly one. The price of that
simplicity: certificates from the old intermediate stay valid, but the CRL
and OCSP answers come from the new one, so they can no longer be revoked;
renewing moves them over.

Certificate profiles (`ca/profiles.go`, `config/profiles.go`) are
the administrator's own, defined from a base. X.509 bases (`tls-server`,
`tls-client`, `email`, `code-signing`) set lifetimes, key usages, the
subject's OU, allowed kinds of names, policy OIDs, extra extensions and key
rules; SSH bases (`ssh-user`, `ssh-host`) set lifetimes, extensions and
critical options. Each template records its base. The CA looks profiles up
by name, the administrator's first (`CA.X509Template`, `CA.SSHTemplate`),
and `IssueX509` and `IssueSSH` enforce them, so they hold for tokens,
logins, ACME, SCEP and renewals alike.

Each verifier names the profiles it issues, under `x509` and `ssh`
(`oidc.x509.cert_profile` and so on), with defaults (`tls-client`,
`ssh-user`, `tls-server` for ACME, `tls-device` for SCEP's shared
challenge). The configuration checks each one's
base against what the verifier may issue: logins get `tls-client` and
`ssh-user` kinds, ACME `tls-server`, the SCEP shared challenge
`tls-client` or `tls-server`.

Under an existing root (`ca/external.go`), BastionXP CA makes no root: `init
--external-root` writes the intermediate key and a CSR, another CA signs
it, and `ImportIntermediate` checks the certificate (the waiting key, a
CA with keyCertSign and cRLSign, a valid chain to the root) before it puts
it in place. The CAs between the intermediate and the root are kept in
`chain.crt` and sent with every certificate (`CA.Chain`); BastionXP CA still has
exactly one intermediate of its own. Replacing it is a new CSR and an
import.

Name constraints (`ca/constraints.go`), if configured, are written into
the intermediate, critical, with every kind of name that is not listed
forbidden outright. `IssueX509` verifies each new certificate against the
chain, as a client would, before it is recorded or handed out.

The SSH CA keys are replaced in two steps (`ca/sshca.go`): a next key is
made and published beside the current one, then activated. The CA signs
with one key at any time. Replaced host CA public keys are kept, so that
host certificates they signed can still be renewed. The command counts them and asks first. The
server's own certificate is recorded as `bastionxp-ca-server` and not counted:
the server replaces it at every start.

Key files are PKCS#8 PEM, plain or encrypted (`internal/keyfile`: PBES2
with scrypt and AES-256-CBC, the standard format OpenSSL reads; files
OpenSSL encrypted with PBKDF2 are read too). The root key is always
encrypted. The keys the server uses (intermediate, SSH CAs, token key)
are encrypted if a passphrase is configured; `serve` takes it from the
configuration, a systemd credential, the environment or the terminal, in
that order (`cmd/bxp/passphrase.go`).

What encryption is for, and what not: it protects copies of the key files
(backups, images, a lost USB stick), as long as the passphrase does not
travel with them. So a passphrase file inside `data_dir` is refused, a
passphrase in the environment is removed from it once read, and the
recommended place is a systemd credential sealed to the TPM. It does not
protect against someone who controls the running server.

## The server's own certificate

The HTTPS server needs a TLS certificate. At startup it creates a key in
memory and asks its own CA for a `tls-server` certificate for the names in
`server.names`. It replaces the certificate automatically after two thirds
of its lifetime. Nothing is written to disk, and clients only need
`root.crt`.

## Packages

| Package           | Job                                                             |
|-------------------|-----------------------------------------------------------------|
| `cmd/bxp`      | The command line: parses flags, loads config, calls the packages below. No logic of its own. |
| `internal/config` | Loads the YAML config file into a struct and validates it.      |
| `internal/ca`     | Creates and loads the CA. Signs X.509 and SSH certificates, CRLs and OCSP answers. Holds the built-in profiles. |
| `internal/token`  | Creates and checks one-time tokens and signed logins.           |
| `internal/policy` | Checks that a request only asks for names the requester may have: for tokens, for people who logged in (rules by user and group), and for ACME. |
| `internal/store`  | The SQLite database: every certificate issued and whether it was revoked, which tokens were used, and the ACME accounts and orders. |
| `internal/server` | The HTTP API, the CA's public information (CRL, OCSP), and the server's own TLS certificate. |
| `internal/api`    | The JSON messages of the HTTP API, shared by server and client. |
| `internal/client` | Talks to a BastionXP CA server. Used by the client commands (`tls`, `ssh`, `token` from afar). |
| `internal/acme`   | The ACME server.                                                |
| `internal/scep`   | The SCEP server and client, and the server's own key (the RA).  |
| `internal/oidc`   | Finds out who a person is with an OIDC identity provider: name and groups. `oidctest` in it is a fake provider for tests, one that can also hand out bad tokens. |
| `internal/metrics` | The counters for Prometheus, written in its text format by hand (no client library). Counts and dates only, never names. |
| `internal/ldap`   | Finds out who a person is from their username and password, with Active Directory or another LDAP server: name and groups. Limits failed logins. `ldaptest` in it is a fake directory for tests that behaves like AD. |

## Design rules

- **The CA package only signs.** It checks that a request is technically
  sound (strong key, sane lifetime, at least one name). It does not decide
  who may have which name. That keeps the security-critical code small.
- **Nothing is issued without a record.** Every certificate is in the
  database before it leaves the CA.
- **One way in.** All X.509 certificates come from `CA.IssueX509`, all SSH
  certificates from `CA.IssueSSH`.
- **No global state.** Configuration is loaded once in `main` and passed down.
- **Fail at startup, not at 3 a.m.** Unknown config keys, mismatched key
  files and broken chains are errors when the program starts.
- **Reload, but never into a broken state.** On SIGHUP the server reads its
  configuration again. The access rules and the ACME domains are swapped in one step each (`atomic.Pointer`), and each
  request takes them once at its start. A file that does not load is
  ignored and the old rules stay. Settings that a running server cannot
  change (addresses, keys, which parts are on) are only reported.
