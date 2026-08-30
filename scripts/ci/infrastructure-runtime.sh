#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

for tool in docker python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required R-10 infrastructure hardening tool not found: $tool" >&2
    exit 1
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose is required for R-10 infrastructure hardening checks" >&2
  exit 1
fi

if grep -n 'tls_insecure_skip_verify' deploy/gateway/Caddyfile deploy/gateway/docker-compose.yml; then
  echo "insecure Caddy upstream TLS configuration is forbidden" >&2
  exit 1
fi
if ! grep -q 'health_uri /readyz' deploy/gateway/Caddyfile; then
  echo "Caddy upstream active health must use Gateway readiness" >&2
  exit 1
fi
if ! grep -q 'tls_trust_pool file /etc/caddy/gateway-ca.pem' deploy/gateway/Caddyfile || \
   ! grep -q 'tls_server_name gateway' deploy/gateway/Caddyfile; then
  echo "Caddy→Gateway verified TLS configuration is incomplete" >&2
  exit 1
fi
if ! grep -q '^USER 10001:10001$' deploy/gateway/Dockerfile; then
  echo "Gateway image must run as the dedicated non-root runtime UID/GID" >&2
  exit 1
fi

# Compose versions differ in whether explicit false bind options survive `config --format json`.
# Verify fail-closed bind-source policy from the authoritative source YAML, then verify
# all other mount/runtime properties from rendered Compose and actual containers.
bind_mounts="$(grep -Ec '^[[:space:]]+- type: bind$' deploy/gateway/docker-compose.yml)"
fail_closed_binds="$(grep -Ec '^[[:space:]]+create_host_path: false$' deploy/gateway/docker-compose.yml)"
if [[ "$bind_mounts" != 6 || "$fail_closed_binds" != "$bind_mounts" ]]; then
  echo "all six Gateway/Caddy bind mounts must set create_host_path: false" >&2
  exit 1
fi

rendered="$(HOOSHIX_PUBLIC_HOST=localhost docker compose -f deploy/gateway/docker-compose.yml config --format json)"
python3 - "$rendered" <<'PY'
import json
import sys

cfg = json.loads(sys.argv[1])
services = cfg.get("services", {})
if set(services) != {"gateway", "caddy"}:
    raise SystemExit(f"unexpected Compose services: {sorted(services)}")

def require(condition, message):
    if not condition:
        raise SystemExit(message)

for name in ("gateway", "caddy"):
    service = services[name]
    require(service.get("read_only") is True, f"{name} root filesystem must be read-only")
    require(service.get("privileged", False) is False, f"{name} must not be privileged")
    require("no-new-privileges:true" in service.get("security_opt", []), f"{name} must enforce no-new-privileges")
    require(service.get("cap_drop") == ["ALL"], f"{name} must drop all ambient capabilities")
    require(service.get("pids_limit") == 256, f"{name} PID ceiling must be explicit")
    require(int(service.get("mem_limit", 0)) == 268435456, f"{name} memory ceiling must be 256 MiB")
    require(service.get("cpus") == 1.0, f"{name} CPU ceiling must be explicit")
    tmpfs = service.get("tmpfs", [])
    require(len(tmpfs) == 1 and tmpfs[0].startswith("/tmp:"), f"{name} must have only the bounded /tmp tmpfs")
    for option in ("noexec", "nosuid", "nodev", "size=16m", "mode=1777"):
        require(option in tmpfs[0], f"{name} /tmp must include {option}")
    require("healthcheck" in service and service["healthcheck"].get("test"), f"{name} healthcheck is required")
    require(service.get("network_mode") not in {"host", "service:host"}, f"{name} host networking is forbidden")
    require(service.get("pid") != "host", f"{name} host PID namespace is forbidden")
    require(service.get("ipc") != "host", f"{name} host IPC namespace is forbidden")
    require(not service.get("devices"), f"{name} device passthrough is forbidden")

require(services["gateway"].get("cap_add", []) == [], "Gateway must not add capabilities")
require(not services["gateway"].get("ports"), "Gateway must not publish host ports")
require(services["caddy"].get("user") == "10001:10001", "Caddy must run as the dedicated non-root UID/GID")
require(services["caddy"].get("cap_add") == ["NET_BIND_SERVICE"], "Caddy may add only NET_BIND_SERVICE")
require(len(services["caddy"].get("ports", [])) == 2, "Caddy must be the only public 80/443 edge")
require(services["caddy"].get("depends_on", {}).get("gateway", {}).get("condition") == "service_healthy", "Caddy must wait for Gateway readiness")

for name, service in services.items():
    for mount in service.get("volumes", []):
        source = str(mount.get("source", ""))
        target = str(mount.get("target", ""))
        require("ca.key" not in source and "ca.key" not in target, "deployment CA private key must never be mounted")
        if mount.get("type") == "bind":
            require(mount.get("read_only") is True, f"{name} bind mount {target} must be read-only")
        if target in {"/data", "/config"}:
            require(name == "caddy" and mount.get("type") == "volume" and not mount.get("read_only", False), f"only Caddy named state volumes may be writable: {target}")

caddy_writable = {m.get("target") for m in services["caddy"].get("volumes", []) if not m.get("read_only", False)}
require(caddy_writable == {"/data", "/config"}, f"unexpected writable Caddy mounts: {sorted(caddy_writable)}")
require(all(m.get("read_only") for m in services["gateway"].get("volumes", [])), "all Gateway persistent mounts must be read-only")
PY

if grep -R -n -E '(control[-_ ]?panel|postgres|mysql|mariadb|redis|kubernetes)' deploy/gateway/docker-compose.yml; then
  echo "Gateway deployment contains an out-of-scope service/infrastructure reference" >&2
  exit 1
fi

echo "R-10 infrastructure runtime hardening gate: PASSED — Compose is two-service only, non-root/read-only, capability-minimal, resource-bounded, fail-closed on bind sources and verified-TLS/readiness-aware."
