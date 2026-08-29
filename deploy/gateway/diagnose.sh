#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

compose=(docker compose)
if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

"${compose[@]}" ps

echo "--- Gateway readiness ---"
"${compose[@]}" exec -T gateway curl --fail --silent --show-error \
  --cacert /run/hooshix-tls/ca.crt \
  https://gateway:8443/readyz
printf '\n'

echo "--- Gateway aggregate metrics ---"
"${compose[@]}" exec -T gateway curl --fail --silent --show-error \
  --cacert /run/hooshix-tls/ca.crt \
  https://gateway:8443/metrics

echo "--- Recent Gateway logs ---"
"${compose[@]}" logs --tail=50 gateway

echo "--- Recent Caddy logs ---"
"${compose[@]}" logs --tail=50 caddy
