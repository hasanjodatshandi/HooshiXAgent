#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

for tool in go docker openssl curl tar gzip unzip zip sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required packaging/operations tool not found: $tool" >&2
    exit 1
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  echo "docker compose is required" >&2
  exit 1
fi

if grep -n 'tls_insecure_skip_verify' deploy/gateway/Caddyfile deploy/gateway/docker-compose.yml; then
  echo "insecure Caddy upstream TLS configuration is forbidden" >&2
  exit 1
fi
if grep -R -n -E '(control[-_ ]?panel|postgres|mysql|mariadb|redis|kubernetes)' deploy/gateway/docker-compose.yml; then
  echo "Gateway deployment bundle contains an out-of-scope service/infrastructure reference" >&2
  exit 1
fi
if ! grep -q 'header_up Host {host}' deploy/gateway/Caddyfile; then
  echo "Caddy must preserve the original public Host for Gateway route lookup" >&2
  exit 1
fi
if ! grep -q 'tls_trust_pool file /etc/caddy/gateway-ca.pem' deploy/gateway/Caddyfile || \
   ! grep -q 'tls_server_name gateway' deploy/gateway/Caddyfile; then
  echo "Caddy→Gateway certificate verification configuration is incomplete" >&2
  exit 1
fi

work="$(mktemp -d)"
compose_started=false
cleanup() {
  if [[ "$compose_started" == true && -d "$work/gateway/deploy/gateway" ]]; then
    (
      cd "$work/gateway/deploy/gateway"
      HOOSHIX_PUBLIC_HOST=localhost \
      HOOSHIX_HTTP_PORT=18080 \
      HOOSHIX_HTTPS_PORT=18443 \
      HOOSHIX_METADATA_DIR="$work/gateway/deploy/gateway/runtime/metadata" \
      HOOSHIX_TLS_DIR="$work/gateway/deploy/gateway/runtime/tls" \
        docker compose down -v --remove-orphans >/dev/null 2>&1 || true
    )
  fi
  rm -rf "$work"
}
trap cleanup EXIT

release_dir="$work/release"
bash scripts/release/build-release.sh v0.0.0-ag7 "$release_dir"
(
  cd "$release_dir"
  sha256sum -c SHA256SUMS
)

# Prove the produced Linux archive itself is a clean installable package.
mkdir -p "$work/agent-package"
tar -xzf "$release_dir/hooshix-agent_v0.0.0-ag7_linux_amd64.tar.gz" -C "$work/agent-package"
HOOSHIX_AGENT_OS=linux HOOSHIX_AGENT_BINARY="$work/agent-package/hooshix-agent" \
  "$work/agent-package/install.sh" \
  --prefix "$work/agent-install/bin" \
  --state-dir "$work/agent-install/state" \
  --service-path "$work/agent-install/hooshix-agent.service" \
  --no-service
"$work/agent-install/bin/hooshix-agent" init --state-dir "$work/agent-install/state" --json >/dev/null
"$work/agent-install/bin/hooshix-agent" status --state-dir "$work/agent-install/state" --json >/dev/null
HOOSHIX_AGENT_OS=linux \
  "$work/agent-package/uninstall.sh" \
  --prefix "$work/agent-install/bin" \
  --state-dir "$work/agent-install/state" \
  --service-path "$work/agent-install/hooshix-agent.service" \
  --no-service --purge-state
[[ ! -e "$work/agent-install/bin/hooshix-agent" ]]

# Prove the produced Gateway deployment bundle is self-contained.
mkdir -p "$work/gateway"
tar -xzf "$release_dir/hooshix-gateway-deploy_v0.0.0-ag7.tar.gz" -C "$work/gateway"
cd "$work/gateway/deploy/gateway"
chmod 755 bootstrap-internal-tls.sh diagnose.sh
HOOSHIX_TLS_DIR="$PWD/runtime/tls" HOOSHIX_METADATA_DIR="$PWD/runtime/metadata" ./bootstrap-internal-tls.sh
[[ -f runtime/tls/ca.key && -f runtime/tls/ca.crt && -f runtime/tls/gateway.crt && -f runtime/tls/gateway.key ]]

services="$({ HOOSHIX_PUBLIC_HOST=localhost docker compose config --services; } | LC_ALL=C sort)"
if [[ "$services" != $'caddy\ngateway' ]]; then
  echo "unexpected Compose services:" >&2
  printf '%s\n' "$services" >&2
  exit 1
fi
compose_rendered="$(HOOSHIX_PUBLIC_HOST=localhost docker compose config)"
if grep -qiE '(control[-_ ]?panel|postgres|mysql|mariadb|redis|kubernetes)' <<<"$compose_rendered"; then
  echo "rendered Compose unexpectedly contains out-of-scope services" >&2
  exit 1
fi
if grep -q 'ca.key' <<<"$compose_rendered"; then
  echo "deployment CA private key must not be mounted into runtime containers" >&2
  exit 1
fi

HOOSHIX_PUBLIC_HOST=localhost \
HOOSHIX_HTTP_PORT=18080 \
HOOSHIX_HTTPS_PORT=18443 \
HOOSHIX_METADATA_DIR="$PWD/runtime/metadata" \
HOOSHIX_TLS_DIR="$PWD/runtime/tls" \
  docker compose up -d --build
compose_started=true

for _ in $(seq 1 60); do
  if curl --fail --insecure --silent --show-error https://localhost:18443/healthz >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl --fail --insecure --silent --show-error https://localhost:18443/healthz | grep -q '"status":"ok"'

ready_public="$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' https://localhost:18443/readyz)"
metrics_public="$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' https://localhost:18443/metrics)"
[[ "$ready_public" == 404 ]]
[[ "$metrics_public" == 404 ]]

internal_ready="$(docker compose exec -T gateway curl --fail --silent --show-error --cacert /run/hooshix-tls/ca.crt https://gateway:8443/readyz)"
[[ "$internal_ready" == *'"status":"ready"'* ]]
internal_metrics="$(docker compose exec -T gateway curl --fail --silent --show-error --cacert /run/hooshix-tls/ca.crt https://gateway:8443/metrics)"
for metric in hooshix_gateway_agent_sessions hooshix_gateway_active_streams hooshix_gateway_pending_handshakes; do
  grep -q "$metric" <<<"$internal_metrics"
done
if grep -q '{' <<<"$internal_metrics"; then
  echo "Gateway operational metrics unexpectedly contain labels" >&2
  exit 1
fi

./diagnose.sh >/dev/null

# Release workflow trust must use OIDC-backed artifact attestations and verify them before publishing.
grep -q 'id-token: write' "$repo_root/.github/workflows/release.yml"
grep -q 'attestations: write' "$repo_root/.github/workflows/release.yml"
grep -Eq 'uses: actions/attest@[0-9a-f]{40} # v4\.' "$repo_root/.github/workflows/release.yml"
grep -q 'gh attestation verify' "$repo_root/.github/workflows/release.yml"
grep -q 'verify-release-commit.py' "$repo_root/.github/workflows/release.yml"
grep -q 'supply-chain-artifacts.sh' "$repo_root/.github/workflows/release.yml"

echo "Packaging/operations gate: PASSED — release archives, clean Agent package install, clean Gateway Compose+Caddy deployment, verified internal TLS, private operational endpoints and release-attestation workflow were exercised."
