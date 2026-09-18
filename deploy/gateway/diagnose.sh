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
  http://127.0.0.1:9090/readyz
printf '\n'

echo "--- Gateway aggregate metrics ---"
"${compose[@]}" exec -T gateway curl --fail --silent --show-error \
  http://127.0.0.1:9090/metrics

echo "--- Recent Gateway logs ---"
"${compose[@]}" logs --tail=50 gateway

echo "--- Recent Caddy logs ---"
"${compose[@]}" logs --tail=50 caddy
