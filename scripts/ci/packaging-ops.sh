#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

for tool in go docker openssl curl tar gzip unzip zip sha256sum python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required packaging/operations tool not found: $tool" >&2
    exit 1
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  echo "docker compose is required" >&2
  exit 1
fi

if grep -n 'tls_insecure_skip_verify' deploy/gateway/Caddyfile deploy/gateway/Caddyfile.static deploy/gateway/docker-compose.yml; then
  echo "insecure Caddy upstream TLS configuration is forbidden" >&2
  exit 1
fi
if grep -R -n -E '(control[-_ ]?panel|postgres|mysql|mariadb|redis|kubernetes)' deploy/gateway/docker-compose.yml; then
  echo "Gateway deployment bundle contains an out-of-scope service/infrastructure reference" >&2
  exit 1
fi
for caddy_config in deploy/gateway/Caddyfile deploy/gateway/Caddyfile.static; do
  if ! grep -q 'header_up Host {host}' "$caddy_config"; then
    echo "Caddy must preserve the original public Host for Gateway route lookup: $caddy_config" >&2
    exit 1
  fi
  if ! grep -q 'tls_trust_pool file /etc/caddy/gateway-ca.pem' "$caddy_config" || \
     ! grep -q 'tls_server_name gateway' "$caddy_config"; then
    echo "Caddy→Gateway certificate verification configuration is incomplete: $caddy_config" >&2
    exit 1
  fi
  # Response hardening: HSTS with at least a six-month max-age, MIME-sniffing
  # protection, and no Server banner on anything the public edge emits.
  if ! grep -Eq 'Strict-Transport-Security "max-age=(15[0-9]{6}|[2-9][0-9]{7,})"' "$caddy_config"; then
    echo "Caddy must emit HSTS with a max-age of at least six months: $caddy_config" >&2
    exit 1
  fi
  if ! grep -q 'X-Content-Type-Options "nosniff"' "$caddy_config"; then
    echo "Caddy must emit X-Content-Type-Options: nosniff: $caddy_config" >&2
    exit 1
  fi
  if ! grep -q -- '-Server' "$caddy_config"; then
    echo "Caddy must suppress the Server response header: $caddy_config" >&2
    exit 1
  fi
  # The edge must refuse the genuinely internal /readyz and /metrics paths, and
  # must NOT refuse /healthz: it is a common tenant health path and the separate
  # ops listener already removed the Gateway-local shadowing, so an edge refusal
  # would make a tenant's own /healthz unreachable.
  if ! grep -q '@internal_ops path /readyz /metrics' "$caddy_config"; then
    echo "Caddy must refuse the internal /readyz and /metrics paths: $caddy_config" >&2
    exit 1
  fi
  if grep -qE '@internal_ops path.*/healthz' "$caddy_config"; then
    echo "Caddy must NOT refuse /healthz on the public edge: $caddy_config" >&2
    exit 1
  fi
done

# The production Caddyfile is only ever adapted inside a running container
# otherwise, so an unsupported on_demand_tls sub-directive (Caddy v2.11.x
# accepts only ask and permission: interval/burst were removed and there is no
# rate_limit) would first surface as a dead edge in production. Adapt it here
# with a syntactically valid ask URL.
caddy_image='caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648'
if ! docker run --rm -e HOOSHIX_TLS_ASK_URL=https://permission.invalid/ask \
  -v "$repo_root/deploy/gateway/Caddyfile:/etc/caddy/Caddyfile:ro" "$caddy_image" \
  caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
  echo "production Caddyfile failed to adapt with a valid HOOSHIX_TLS_ASK_URL" >&2
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
      HOOSHIX_METADATA_MODE=static \
      HOOSHIX_CADDYFILE=./Caddyfile.static \
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

services="$({ HOOSHIX_PUBLIC_HOST=localhost HOOSHIX_CADDYFILE=./Caddyfile.static docker compose config --services; } | LC_ALL=C sort)"
if [[ "$services" != $'caddy\ngateway' ]]; then
  echo "unexpected Compose services:" >&2
  printf '%s\n' "$services" >&2
  exit 1
fi
compose_rendered="$(HOOSHIX_PUBLIC_HOST=localhost HOOSHIX_CADDYFILE=./Caddyfile.static docker compose config)"
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
HOOSHIX_METADATA_MODE=static \
HOOSHIX_CADDYFILE=./Caddyfile.static \
HOOSHIX_METADATA_DIR="$PWD/runtime/metadata" \
HOOSHIX_TLS_DIR="$PWD/runtime/tls" \
  docker compose up -d --build
compose_started=true

# The Gateway's liveness/readiness/metrics live on the loopback administrative
# listener, so readiness is observed through the container healthcheck.
for _ in $(seq 1 60); do
  gateway_health="$(docker inspect --format '{{.State.Health.Status}}' "$(docker compose ps -q gateway)" 2>/dev/null || true)"
  if [[ "$gateway_health" == healthy ]]; then
    break
  fi
  sleep 1
done
[[ "$gateway_health" == healthy ]]

# Verify the public edge certificate instead of skipping verification: the
# localhost certificate is issued by Caddy's own internal CA, whose root is
# available inside the container (the same source the RA-4 gate uses).
docker compose exec -T caddy cat /data/caddy/pki/authorities/local/root.crt >"$work/caddy-root.crt"
openssl x509 -in "$work/caddy-root.crt" -noout >/dev/null

# The edge must refuse the internal /readyz and /metrics paths itself (404).
# /healthz is deliberately not refused and is therefore not probed here: this
# static fixture has no route for it, so it would answer 404 from the Gateway's
# no-route path, not from an edge refusal — asserting a status for it would be
# meaningless. The Caddyfile assertion earlier in this script is authoritative
# for the refused-path list.
ready_public="$(curl --cacert "$work/caddy-root.crt" --silent --output /dev/null --write-out '%{http_code}' https://localhost:18443/readyz)"
metrics_public="$(curl --cacert "$work/caddy-root.crt" --silent --output /dev/null --write-out '%{http_code}' https://localhost:18443/metrics)"
[[ "$ready_public" == 404 ]]
[[ "$metrics_public" == 404 ]]

internal_ready="$(docker compose exec -T gateway curl --fail --silent --show-error http://127.0.0.1:9090/readyz)"
[[ "$internal_ready" == *'"status":"ready"'* ]]
internal_metrics="$(docker compose exec -T gateway curl --fail --silent --show-error http://127.0.0.1:9090/metrics)"
for metric in hooshix_gateway_agent_sessions hooshix_gateway_active_streams hooshix_gateway_pending_handshakes; do
  grep -q "$metric" <<<"$internal_metrics"
done
if grep -q '{' <<<"$internal_metrics"; then
  echo "Gateway operational metrics unexpectedly contain labels" >&2
  exit 1
fi

# R-10: prove the rendered policy survives into actual container HostConfig/Mounts.
gateway_id="$(docker compose ps -q gateway)"
caddy_id="$(docker compose ps -q caddy)"
[[ -n "$gateway_id" && -n "$caddy_id" ]]
python3 - "$gateway_id" "$caddy_id" <<'PY'
import json
import subprocess
import sys

ids = {"gateway": sys.argv[1], "caddy": sys.argv[2]}
inspected = {}
for name, container_id in ids.items():
    inspected[name] = json.loads(subprocess.check_output(["docker", "inspect", container_id], text=True))[0]

def require(condition, message):
    if not condition:
        raise SystemExit(message)

for name, obj in inspected.items():
    host = obj["HostConfig"]
    cfg = obj["Config"]
    require(host["Privileged"] is False, f"{name} unexpectedly privileged")
    require(host["ReadonlyRootfs"] is True, f"{name} root filesystem not read-only")
    require("no-new-privileges:true" in host.get("SecurityOpt", []), f"{name} missing no-new-privileges")
    require(host.get("CapDrop") == ["ALL"], f"{name} must drop all capabilities")
    require(host.get("PidsLimit") == 256, f"{name} PID limit mismatch")
    require(host.get("Memory") == 268435456, f"{name} memory limit mismatch")
    require(host.get("NanoCpus") == 1000000000, f"{name} CPU limit mismatch")
    require(host.get("NetworkMode") != "host", f"{name} host networking forbidden")
    require(host.get("PidMode", "") != "host", f"{name} host PID namespace forbidden")
    require(host.get("IpcMode", "") != "host", f"{name} host IPC namespace forbidden")
    require(not host.get("Devices"), f"{name} device passthrough forbidden")
    tmpfs = host.get("Tmpfs", {}).get("/tmp", "")
    for option in ("noexec", "nosuid", "nodev", "size=16m", "mode=1777"):
        require(option in tmpfs, f"{name} /tmp missing {option}")

require(inspected["gateway"]["Config"].get("User") == "10001:10001", "Gateway runtime user mismatch")
require(inspected["gateway"]["HostConfig"].get("CapAdd") in (None, []), "Gateway added capabilities")
require(inspected["caddy"]["Config"].get("User") == "10001:10001", "Caddy must run non-root")
require(inspected["caddy"]["HostConfig"].get("CapAdd") == ["CAP_NET_BIND_SERVICE"], "Caddy capability set is not minimal")

for name, obj in inspected.items():
    for mount in obj.get("Mounts", []):
        source = str(mount.get("Source", ""))
        destination = str(mount.get("Destination", ""))
        require("ca.key" not in source and "ca.key" not in destination, "CA private key mounted at runtime")
        if mount.get("Type") == "bind":
            require(mount.get("RW") is False, f"{name} bind mount is writable: {destination}")

caddy_writable = {m["Destination"] for m in inspected["caddy"].get("Mounts", []) if m.get("RW")}
require(caddy_writable == {"/data", "/config"}, f"unexpected writable Caddy mounts: {sorted(caddy_writable)}")
require(not any(m.get("RW") for m in inspected["gateway"].get("Mounts", [])), "Gateway has writable persistent mount")
PY

gateway_health=""
caddy_health=""
for _ in $(seq 1 30); do
  gateway_health="$(docker inspect --format '{{.State.Health.Status}}' "$gateway_id")"
  caddy_health="$(docker inspect --format '{{.State.Health.Status}}' "$caddy_id")"
  if [[ "$gateway_health" == healthy && "$caddy_health" == healthy ]]; then
    break
  fi
  sleep 1
done
[[ "$gateway_health" == healthy ]]
[[ "$caddy_health" == healthy ]]

./diagnose.sh >/dev/null

# Release workflow trust must use OIDC-backed artifact attestations and verify them before publishing.
grep -q 'id-token: write' "$repo_root/.github/workflows/release.yml"
grep -q 'attestations: write' "$repo_root/.github/workflows/release.yml"
grep -Eq 'uses: actions/attest@[0-9a-f]{40} # v4\.' "$repo_root/.github/workflows/release.yml"
grep -q 'gh attestation verify' "$repo_root/.github/workflows/release.yml"
grep -q 'verify-release-commit.py' "$repo_root/.github/workflows/release.yml"
grep -q 'supply-chain-artifacts.sh' "$repo_root/.github/workflows/release.yml"

echo "Packaging/operations gate: PASSED — release archives, clean Agent package install, clean Gateway Compose+Caddy deployment, verified internal TLS, private operational endpoints and release-attestation workflow were exercised."
