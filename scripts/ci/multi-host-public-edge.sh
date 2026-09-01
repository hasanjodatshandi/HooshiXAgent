#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

for tool in go docker openssl curl python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required RA-4 multi-host tool not found: $tool" >&2
    exit 1
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose is required for RA-4 multi-host acceptance" >&2
  exit 1
fi

caddy_image='caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648'
one_host='one.ra4.hooshix.test'
two_host='two.ra4.hooshix.test'
approved_no_route='approved-no-route.ra4.hooshix.test'
unknown_host='unknown.ra4.hooshix.test'

# Production dynamic mode must fail closed if the external permission authority is not configured.
if docker run --rm -e HOOSHIX_TLS_ASK_URL= \
  -v "$repo_root/deploy/gateway/Caddyfile:/etc/caddy/Caddyfile:ro" "$caddy_image" \
  caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
  echo "production Caddyfile unexpectedly adapted without HOOSHIX_TLS_ASK_URL" >&2
  exit 1
fi

project="hooshix-ra4-$RANDOM-$$"
permission_container="${project}-permission"
work="$(mktemp -d)"
agent_pid=''
backend_one_pid=''
backend_two_pid=''
compose_started=false

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PY
}

http_port="$(free_port)"
https_port="$(free_port)"
backend_one_port="$(free_port)"
backend_two_port="$(free_port)"
metadata_dir="$work/metadata"
tls_dir="$work/tls"
state_dir="$work/agent-state"
agent_binary="$work/hooshix-agent"
test_caddyfile="$work/Caddyfile.ra4-test"
permission_caddyfile="$work/Caddyfile.permission"
caddy_root="$work/caddy-root.crt"

cleanup() {
  set +e
  if [[ -n "$agent_pid" ]]; then kill "$agent_pid" >/dev/null 2>&1 || true; wait "$agent_pid" >/dev/null 2>&1 || true; fi
  if [[ -n "$backend_one_pid" ]]; then kill "$backend_one_pid" >/dev/null 2>&1 || true; wait "$backend_one_pid" >/dev/null 2>&1 || true; fi
  if [[ -n "$backend_two_pid" ]]; then kill "$backend_two_pid" >/dev/null 2>&1 || true; wait "$backend_two_pid" >/dev/null 2>&1 || true; fi
  docker rm -f "$permission_container" >/dev/null 2>&1 || true
  if [[ "$compose_started" == true ]]; then
    HOOSHIX_PUBLIC_HOST="$one_host" \
    HOOSHIX_HTTP_PORT="$http_port" \
    HOOSHIX_HTTPS_PORT="$https_port" \
    HOOSHIX_METADATA_MODE=static \
    HOOSHIX_CADDYFILE="$test_caddyfile" \
    HOOSHIX_TLS_ASK_URL="http://$permission_container:8080/ask" \
    HOOSHIX_METADATA_DIR="$metadata_dir" \
    HOOSHIX_TLS_DIR="$tls_dir" \
      docker compose -p "$project" -f deploy/gateway/docker-compose.yml down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

mkdir -p "$metadata_dir" "$tls_dir" "$state_dir"
HOOSHIX_TLS_DIR="$tls_dir" HOOSHIX_METADATA_DIR="$metadata_dir" deploy/gateway/bootstrap-internal-tls.sh >/dev/null

go build -o "$agent_binary" ./cmd/agent
identity_json="$($agent_binary init --state-dir "$state_dir" --json)"
public_key="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["public_key"])' <<<"$identity_json")"
token="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
token_sha="$(printf '%s' "$token" | sha256sum | awk '{print $1}')"

python3 - "$metadata_dir" "$public_key" "$token_sha" "$one_host" "$two_host" <<'PY'
import json, os, sys
from datetime import datetime, timedelta, timezone
root, public_key, token_sha, one_host, two_host = sys.argv[1:]
now = datetime.now(timezone.utc).replace(microsecond=0)
def ts(d): return d.isoformat().replace('+00:00', 'Z')
auth = {
    'contract_version': 1,
    'authorization_id': 'auth-ra4-001',
    'device_id': 'device-ra4-001',
    'device_public_key': public_key,
    'token_id': 'token-ra4-001',
    'token_sha256': token_sha,
    'issued_at': ts(now - timedelta(minutes=1)),
    'not_before': ts(now - timedelta(minutes=1)),
    'expires_at': ts(now + timedelta(hours=1)),
    'disabled': False,
}
routes = [
    {
        'contract_version': 1,
        'assignment_id': 'assign-ra4-001',
        'endpoint_id': 'endpoint-ra4-001',
        'public_hostname': one_host,
        'device_id': 'device-ra4-001',
        'local_endpoint_id': 'local-ra4-one',
        'enabled': True,
        'not_before': ts(now - timedelta(minutes=1)),
        'expires_at': ts(now + timedelta(hours=1)),
    },
    {
        'contract_version': 1,
        'assignment_id': 'assign-ra4-002',
        'endpoint_id': 'endpoint-ra4-002',
        'public_hostname': two_host,
        'device_id': 'device-ra4-001',
        'local_endpoint_id': 'local-ra4-two',
        'enabled': True,
        'not_before': ts(now - timedelta(minutes=1)),
        'expires_at': ts(now + timedelta(hours=1)),
    },
]
os.makedirs(os.path.join(root, 'authorizations'), exist_ok=True)
os.makedirs(os.path.join(root, 'routes'), exist_ok=True)
os.makedirs(os.path.join(root, 'revocations'), exist_ok=True)
with open(os.path.join(root, 'authorizations', 'authorization.json'), 'w', encoding='utf-8') as f: json.dump(auth, f)
for idx, route in enumerate(routes, 1):
    with open(os.path.join(root, 'routes', f'route-{idx}.json'), 'w', encoding='utf-8') as f: json.dump(route, f)
PY

# Test-only variant: production structure is unchanged except that public ACME issuance is replaced
# by Caddy's internal issuer to avoid external CA traffic/rate limits in deterministic CI.
python3 - deploy/gateway/Caddyfile "$test_caddyfile" <<'PY'
from pathlib import Path
import sys
src = Path(sys.argv[1]).read_text(encoding='utf-8')
needle = '\t\ton_demand\n'
if needle not in src:
    raise SystemExit('production Caddyfile on_demand directive missing')
Path(sys.argv[2]).write_text(src.replace(needle, needle + '\t\tissuer internal\n', 1), encoding='utf-8')
PY

cat >"$permission_caddyfile" <<EOF
:8080 {
	@approved query domain=$one_host domain=$two_host domain=$approved_no_route domain=localhost
	respond @approved 200
	respond 403
}
EOF

cat >"$work/backend.py" <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys
label, port = sys.argv[1], int(sys.argv[2])
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (label + ':' + self.path).encode()
        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_POST(self): self.do_GET()
    def log_message(self, *_): pass
ThreadingHTTPServer(('127.0.0.1', port), H).serve_forever()
PY
python3 "$work/backend.py" backend-one "$backend_one_port" & backend_one_pid=$!
python3 "$work/backend.py" backend-two "$backend_two_port" & backend_two_pid=$!

compose_env=(
  HOOSHIX_PUBLIC_HOST="$one_host"
  HOOSHIX_HTTP_PORT="$http_port"
  HOOSHIX_HTTPS_PORT="$https_port"
  HOOSHIX_METADATA_MODE=static
  HOOSHIX_CADDYFILE="$test_caddyfile"
  HOOSHIX_TLS_ASK_URL="http://$permission_container:8080/ask"
  HOOSHIX_METADATA_DIR="$metadata_dir"
  HOOSHIX_TLS_DIR="$tls_dir"
)
env "${compose_env[@]}" docker compose -p "$project" -f deploy/gateway/docker-compose.yml up -d --build gateway
compose_started=true

for _ in $(seq 1 60); do
  gateway_id="$(env "${compose_env[@]}" docker compose -p "$project" -f deploy/gateway/docker-compose.yml ps -q gateway)"
  if [[ -n "$gateway_id" && "$(docker inspect --format '{{.State.Health.Status}}' "$gateway_id" 2>/dev/null || true)" == healthy ]]; then break; fi
  sleep 0.5
done
gateway_id="$(env "${compose_env[@]}" docker compose -p "$project" -f deploy/gateway/docker-compose.yml ps -q gateway)"
[[ -n "$gateway_id" && "$(docker inspect --format '{{.State.Health.Status}}' "$gateway_id")" == healthy ]]

network_name="${project}_edge"
docker run -d --name "$permission_container" --network "$network_name" \
  -v "$permission_caddyfile:/etc/caddy/Caddyfile:ro" "$caddy_image" >/dev/null

env "${compose_env[@]}" docker compose -p "$project" -f deploy/gateway/docker-compose.yml up -d caddy

for _ in $(seq 1 90); do
  if curl --noproxy '*' --insecure --silent --show-error --resolve "$one_host:$https_port:127.0.0.1" "https://$one_host:$https_port/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
if ! curl --noproxy '*' --insecure --fail --silent --show-error --resolve "$one_host:$https_port:127.0.0.1" "https://$one_host:$https_port/healthz" >/dev/null; then
  echo "Caddy did not establish approved-host public TLS" >&2
  docker logs --tail 80 "$permission_container" >&2 || true
  env "${compose_env[@]}" docker compose -p "$project" -f deploy/gateway/docker-compose.yml logs --tail=80 caddy gateway >&2 || true
  exit 1
fi

env "${compose_env[@]}" docker compose -p "$project" -f deploy/gateway/docker-compose.yml exec -T caddy \
  cat /data/caddy/pki/authorities/local/root.crt >"$caddy_root"
openssl x509 -in "$caddy_root" -noout >/dev/null

printf '%s\n' "$token" | "$agent_binary" configure --state-dir "$state_dir" \
  --gateway "wss://localhost:$https_port/agent/v1/connect" --ca-file "$caddy_root" \
  --device-id device-ra4-001 --authorization-id auth-ra4-001 --token-id token-ra4-001 --token-stdin >/dev/null
"$agent_binary" expose add --state-dir "$state_dir" --id local-ra4-one --target "127.0.0.1:$backend_one_port" >/dev/null
"$agent_binary" expose add --state-dir "$state_dir" --id local-ra4-two --target "127.0.0.1:$backend_two_port" >/dev/null
"$agent_binary" run --state-dir "$state_dir" >"$work/agent.stdout" 2>"$work/agent.stderr" & agent_pid=$!

request_host() {
  local host="$1" path="$2"
  curl --noproxy '*' --cacert "$caddy_root" --fail --silent --show-error \
    --resolve "$host:$https_port:127.0.0.1" "https://$host:$https_port$path"
}

body_one=''
body_two=''
for _ in $(seq 1 60); do
  body_one="$(request_host "$one_host" /alpha 2>/dev/null || true)"
  body_two="$(request_host "$two_host" /beta 2>/dev/null || true)"
  if [[ "$body_one" == 'backend-one:/alpha' && "$body_two" == 'backend-two:/beta' ]]; then break; fi
  sleep 0.5
done
if [[ "$body_one" != 'backend-one:/alpha' || "$body_two" != 'backend-two:/beta' ]]; then
  echo "multi-host tunnel responses did not converge: one=$body_one two=$body_two" >&2
  tail -n 80 "$work/agent.stderr" >&2 || true
  env "${compose_env[@]}" docker compose -p "$project" -f deploy/gateway/docker-compose.yml logs --tail=80 caddy gateway >&2 || true
  exit 1
fi

# TLS permission and Gateway route authorization are independent. This hostname is allowed to
# obtain a test certificate but has no route metadata, therefore HTTP must still fail at Gateway.
no_route_status="$(curl --noproxy '*' --cacert "$caddy_root" --silent --output /dev/null --write-out '%{http_code}' \
  --resolve "$approved_no_route:$https_port:127.0.0.1" "https://$approved_no_route:$https_port/no-route")"
[[ "$no_route_status" == 404 ]]

# An unknown hostname is denied by the ask endpoint before Caddy can obtain/manage a certificate.
if curl --noproxy '*' --cacert "$caddy_root" --silent --output /dev/null \
  --resolve "$unknown_host:$https_port:127.0.0.1" "https://$unknown_host:$https_port/unknown" 2>/dev/null; then
  echo "unknown hostname unexpectedly completed TLS through restricted On-Demand TLS" >&2
  exit 1
fi
if env "${compose_env[@]}" docker compose -p "$project" -f deploy/gateway/docker-compose.yml exec -T caddy \
  sh -c "find /data/caddy/certificates -type f -print | grep -F '$unknown_host'" >/dev/null 2>&1; then
  echo "unknown hostname unexpectedly appeared in Caddy certificate storage" >&2
  exit 1
fi

for path in /readyz /metrics; do
  status="$(curl --noproxy '*' --cacert "$caddy_root" --silent --output /dev/null --write-out '%{http_code}' \
    --resolve "$one_host:$https_port:127.0.0.1" "https://$one_host:$https_port$path")"
  [[ "$status" == 404 ]]
done

# The public edge must preserve verified TLS to Gateway in both production and static compatibility configs.
for config in deploy/gateway/Caddyfile deploy/gateway/Caddyfile.static; do
  grep -q 'tls_trust_pool file /etc/caddy/gateway-ca.pem' "$config"
  grep -q 'tls_server_name gateway' "$config"
  if grep -q 'tls_insecure_skip_verify' "$config"; then
    echo "insecure Caddy-to-Gateway TLS found in $config" >&2
    exit 1
  fi
done

echo "RA-4 multi-host public edge gate: PASSED - two approved hostnames simultaneously reached distinct real Agent local endpoints through Caddy; approved-without-route remained 404; unknown TLS authority was denied; operational endpoints stayed private; verified Caddy-to-Gateway TLS remained enabled."
