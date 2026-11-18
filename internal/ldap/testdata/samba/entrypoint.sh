#!/bin/sh
# Provisions the domain corp.example.com at the first start and runs Samba
# in the foreground.
set -eu

: "${ADMIN_PASSWORD:=Admin-pw-2026!}"
TLS=/var/lib/samba/private/tls-test

if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  rm -f /etc/samba/smb.conf
  samba-tool domain provision \
    --realm=CORP.EXAMPLE.COM --domain=CORP --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --adminpass="$ADMIN_PASSWORD"

  # A certificate for 127.0.0.1, issued by a CA of its own, like a domain
  # controller's certificate from AD CS. The test trusts ca.pem.
  mkdir -p "$TLS"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$TLS/ca.key" -out "$TLS/ca.pem" -days 2 -subj "/CN=Test Corp Root CA" 2>/dev/null
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$TLS/key.pem" -out "$TLS/req.csr" -subj "/CN=dc1.corp.example.com" 2>/dev/null
  printf 'subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:dc1.corp.example.com\nextendedKeyUsage=serverAuth\n' > "$TLS/ext.cnf"
  openssl x509 -req -in "$TLS/req.csr" -CA "$TLS/ca.pem" -CAkey "$TLS/ca.key" -CAcreateserial \
    -out "$TLS/cert.pem" -days 2 -extfile "$TLS/ext.cnf" 2>/dev/null
  chmod 600 "$TLS/key.pem"
  sed -i "/\[global\]/a \\
\ttls enabled = yes\\
\ttls keyfile = $TLS/key.pem\\
\ttls certfile = $TLS/cert.pem\\
\ttls cafile = $TLS/ca.pem" /etc/samba/smb.conf
fi

exec samba --foreground --no-process-group --debug-stdout
