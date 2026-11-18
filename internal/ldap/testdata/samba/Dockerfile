# Copyright 2026 Ampas Labs Inc.
# SPDX-License-Identifier: Apache-2.0

# A Samba Active Directory domain controller, for BastionXP CA's LDAP tests only.
# Not for production: the passwords are fixed and known.
#
#   BXP_TEST_SAMBA=1 go test ./internal/ldap -run Samba -v
#
# The test builds this image, starts it, creates people and groups with
# samba-tool, and removes the container at the end.
FROM debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      samba samba-ad-dc samba-ad-provision winbind krb5-user ldb-tools openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 389 636
ENTRYPOINT ["/entrypoint.sh"]
