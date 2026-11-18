# Security policy

BastionXP CA is a certificate authority: a flaw in it can let someone get a
certificate they should not have. Reports are welcome and taken seriously.

## Reporting a vulnerability

**Please do not open a public issue.** Report it privately through
GitHub: on the repository page, open the **Security** tab and choose
**Report a vulnerability**. Only the maintainers see the report.

Please include:

- what an attacker can do, and what they need to start with (network
  access only? a valid token? an account at the identity provider?);
- the steps to reproduce it, or a test that shows it;
- the bxp version (`bxp --version`) and the relevant part of the
  configuration, without secrets.

## What happens next

- You get an answer within 7 days.
- We confirm the problem, agree on a fix and a date with you, and keep you
  informed.
- The fix is released with a security advisory that credits you, unless
  you prefer otherwise.

Please give us reasonable time to release a fix before you publish
details.

## Supported versions

Only the latest release gets security fixes.

## Scope

In scope: anything that lets someone get a certificate, a token or an
admin right they should not have; read or use the CA's keys; get around a
verifier (one-time token, OIDC or LDAP login, ACME, SCEP, renewal); make
revocation lie; or break the server for others.

Out of scope: attacks that need root on the CA machine or the CA's own
configuration file, and weaknesses in the identity provider, the
directory or the operating system themselves.
