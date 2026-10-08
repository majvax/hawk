#!/usr/bin/env bash
# Generates a self-signed TLS cert/key for local development only.
# Not for anything that crosses a real network — see README.md's TLS section.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p certs

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/dev-key.pem \
  -out certs/dev-cert.pem \
  -subj "/CN=hawk-service-dev" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Wrote certs/dev-cert.pem and certs/dev-key.pem"
