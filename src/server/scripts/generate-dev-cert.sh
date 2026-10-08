#!/usr/bin/env bash
# Generates a self-signed TLS cert/key for local development only.
# Not for anything that crosses a real network — see README.md's TLS section.
#
# Usage: bun run certs [-- <ip or hostname>...]
#   Extra arguments are added to the cert alongside localhost/127.0.0.1, so
#   other machines on the LAN can reach the relay by that address, e.g.
#   `bun run certs -- 192.168.1.150 my-pc`.
#
# An existing certs/dev-key.pem is reused rather than replaced: machines pin
# the relay's key (see README.md), so a new key would lock every enrolled
# machine out until it's reinstalled with the new -RelayPin.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p certs

san="DNS:localhost,IP:127.0.0.1"
ipv4='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
for name in "$@"; do
  if [[ "$name" =~ $ipv4 || "$name" == *:* ]]; then
    san+=",IP:$name"
  else
    san+=",DNS:$name"
  fi
done

if [[ -f certs/dev-key.pem ]]; then
  key_args=(-key certs/dev-key.pem)
  echo "Reusing certs/dev-key.pem (the relay's pin is unchanged)"
else
  key_args=(-newkey rsa:2048 -noenc -keyout certs/dev-key.pem)
fi

openssl req -x509 "${key_args[@]}" -days 365 \
  -out certs/dev-cert.pem \
  -subj "/CN=hawk-service-dev" \
  -addext "subjectAltName=$san"

echo "Wrote certs/dev-cert.pem for $san"
