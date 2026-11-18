#!/usr/bin/env bash
# Copyright 2026 Ampas Labs Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Smoke test of the container image, used as docs/server/container.md says:
# init with the root key out of the volume, serve as the non-root user with
# the data in a volume, then a certificate from the host, checked with
# openssl, and a clean stop.
#
#   test/container/smoke.sh <image>      (make test-container builds one)
#
# Run it from the repository root: it builds the client, bxp, for the host.

set -euo pipefail

image="${1:?usage: test/container/smoke.sh <image>}"
work="$(mktemp -d)"
name="bxp-smoke-$$"
volume="bxp-smoke-$$"
port=18443

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "--- server log ---"
    docker logs "$name" 2>&1 | tail -40 || true
  fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

step() { echo "==> $*"; }

# The configuration and the root passphrase, readable by the container's
# user (uid 65532); a folder it may write the root key to.
cat > "$work/bastionxp-ca.yaml" <<YAML
data_dir: /var/lib/bastionxp-ca
ca:
  organization: Container Smoke Test
server:
  address: ":8443"
  names: [localhost, 127.0.0.1]
YAML
echo "container smoke test root passphrase" > "$work/root-passphrase"
mkdir "$work/offline"
chmod 644 "$work/bastionxp-ca.yaml" "$work/root-passphrase"
chmod 777 "$work/offline"
config=(-v "$work/bastionxp-ca.yaml:/etc/bastionxp-ca/bastionxp-ca.yaml:ro")
data=(-v "$volume:/var/lib/bastionxp-ca")

step "version"
docker run --rm "$image" --version | tee /dev/stderr | grep -q "^bxp version "

step "init, the root key outside the volume"
docker run --rm "${data[@]}" "${config[@]}" -v "$work/offline:/offline" \
  -v "$work/root-passphrase:/run/root-passphrase:ro" \
  "$image" init --config /etc/bastionxp-ca/bastionxp-ca.yaml \
  --root-key-out /offline/root.key --root-passphrase-file /run/root-passphrase >/dev/null
test -s "$work/offline/root.key"

step "serve"
docker run -d --name "$name" -p "127.0.0.1:$port:8443" "${data[@]}" "${config[@]}" "$image" >/dev/null

step "build the client for this machine"
go build -o "$work/bxp" ./cmd/bxp
export BXP_CLIENT_DIR="$work/client"

step "trust, once the server answers"
fingerprint="$(docker exec "$name" /usr/local/bin/bxp fingerprint --config /etc/bastionxp-ca/bastionxp-ca.yaml 2>/dev/null)"
for i in $(seq 1 30); do
  if "$work/bxp" trust --ca-url "https://localhost:$port" --fingerprint "$fingerprint" >/dev/null 2>&1; then
    break
  fi
  [ "$i" -eq 30 ] && { echo "the server did not answer"; exit 1; }
  sleep 1
done

step "a certificate from the host"
token="$(docker exec "$name" /usr/local/bin/bxp token --config /etc/bastionxp-ca/bastionxp-ca.yaml \
  --profile tls-server --name web.smoke.test)"
"$work/bxp" tls --token "$token" --out-dir "$work" >/dev/null
docker cp -q "$name:/var/lib/bastionxp-ca/root.crt" "$work/root.crt"
openssl verify -CAfile "$work/root.crt" -untrusted "$work/web.smoke.test.crt" "$work/web.smoke.test.crt"

step "the CA lists it"
docker exec "$name" /usr/local/bin/bxp list certificates --config /etc/bastionxp-ca/bastionxp-ca.yaml |
  grep -q "web.smoke.test"

step "a clean stop"
docker stop "$name" >/dev/null
code="$(docker inspect -f '{{.State.ExitCode}}' "$name")"
[ "$code" -eq 0 ] || { echo "the server exited with status $code"; exit 1; }

echo "container smoke test passed"
