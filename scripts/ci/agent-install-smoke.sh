#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

case "$(uname -s)" in
  Linux) os_name=linux ;;
  Darwin) os_name=darwin ;;
  *) echo "unsupported Unix smoke-test platform" >&2; exit 2 ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
stage="$work/package"
prefix="$work/install/bin"
state="$work/install/state"
service="$work/install/persistence.spec"
mkdir -p "$stage"

go build -o "$stage/hooshix-agent" ./cmd/agent
cp packaging/agent/unix/install.sh packaging/agent/unix/uninstall.sh "$stage/"
chmod 755 "$stage/hooshix-agent" "$stage/install.sh" "$stage/uninstall.sh"

unsafe_home="$work/unsafe-home"
mkdir -p "$unsafe_home"
touch "$unsafe_home/sentinel"
if HOME="$unsafe_home" HOOSHIX_AGENT_OS="$os_name" HOOSHIX_AGENT_BINARY="$stage/hooshix-agent" \
  "$stage/install.sh" --prefix "$work/unsafe-bin" --state-dir "$unsafe_home" --service-path "$work/unsafe-service" --no-service >/dev/null 2>&1; then
  echo "Agent installer unexpectedly accepted the user home as state directory" >&2
  exit 1
fi
if HOME="$unsafe_home" HOOSHIX_AGENT_OS="$os_name" \
  "$stage/uninstall.sh" --prefix "$work/unsafe-bin" --state-dir "$unsafe_home" --service-path "$work/unsafe-service" --no-service --purge-state >/dev/null 2>&1; then
  echo "Agent uninstaller unexpectedly accepted the user home as purge target" >&2
  exit 1
fi
[[ -f "$unsafe_home/sentinel" ]]
unsafe_target="$work/unsafe-target"
unsafe_link="$work/unsafe-link"
mkdir -p "$unsafe_target"
touch "$unsafe_target/sentinel"
ln -s "$unsafe_target" "$unsafe_link"
if HOOSHIX_AGENT_OS="$os_name" "$stage/uninstall.sh" --prefix "$work/unsafe-bin" --state-dir "$unsafe_link" --service-path "$work/unsafe-service" --no-service --purge-state >/dev/null 2>&1; then
  echo "Agent uninstaller unexpectedly accepted a symlink purge target" >&2
  exit 1
fi
[[ -f "$unsafe_target/sentinel" ]]

HOOSHIX_AGENT_OS="$os_name" HOOSHIX_AGENT_BINARY="$stage/hooshix-agent" \
  "$stage/install.sh" --prefix "$prefix" --state-dir "$state" --service-path "$service" --no-service
"$prefix/hooshix-agent" init --state-dir "$state" --json >/dev/null
"$prefix/hooshix-agent" status --state-dir "$state" --json >/dev/null
[[ "$(cat "$state/.hooshix-agent-state")" == "hooshix-agent-state-v1" ]]

# Real cross-process read-modify-write burst must retain every endpoint.
pids=()
for ((i=1; i<=24; i++)); do
  printf -v endpoint_id 'parallel-%03d' "$i"
  "$prefix/hooshix-agent" expose add --state-dir "$state" --id "$endpoint_id" --target 127.0.0.1:8080 >/dev/null &
  pids+=("$!")
done
for pid in "${pids[@]}"; do wait "$pid"; done
endpoints_json="$("$prefix/hooshix-agent" expose list --state-dir "$state" --json)"
python3 -c 'import json,sys; data=json.load(sys.stdin); assert len(data)==24, len(data)' <<<"$endpoints_json"

# Dangerous installer/uninstaller paths must fail before destructive work.
if HOOSHIX_AGENT_OS="$os_name" HOOSHIX_AGENT_BINARY="$stage/hooshix-agent" \
  "$stage/install.sh" --prefix "$prefix" --state-dir / --service-path "$service" --no-service >/dev/null 2>&1; then
  echo "installer accepted filesystem root as Agent state" >&2; exit 1
fi
if HOOSHIX_AGENT_OS="$os_name" \
  "$stage/uninstall.sh" --prefix "$prefix" --state-dir / --service-path "$service" --no-service --purge-state >/dev/null 2>&1; then
  echo "uninstaller accepted filesystem root purge" >&2; exit 1
fi
unowned="$work/unowned/state"
mkdir -p "$unowned"
printf '%s\n' keep >"$unowned/sentinel"
if HOOSHIX_AGENT_OS="$os_name" \
  "$stage/uninstall.sh" --prefix "$prefix" --state-dir "$unowned" --service-path "$service" --no-service --purge-state >/dev/null 2>&1; then
  echo "uninstaller accepted unowned state directory" >&2; exit 1
fi
[[ "$(cat "$unowned/sentinel")" == keep ]]
marker_source="$work/marker-source"
printf '%s
' hooshix-agent-state-v1 >"$marker_source"
marker_symlink_state="$work/marker-symlink/state"
mkdir -p "$marker_symlink_state"
printf '%s
' keep >"$marker_symlink_state/sentinel"
ln -s "$marker_source" "$marker_symlink_state/.hooshix-agent-state"
if HOOSHIX_AGENT_OS="$os_name"   "$stage/uninstall.sh" --prefix "$prefix" --state-dir "$marker_symlink_state" --service-path "$service" --no-service --purge-state >/dev/null 2>&1; then
  echo "uninstaller accepted symlink Agent state marker" >&2; exit 1
fi
[[ "$(cat "$marker_symlink_state/sentinel")" == keep ]]
victim="$work/victim/state"
mkdir -p "$victim"
printf '%s\n' hooshix-agent-state-v1 >"$victim/.hooshix-agent-state"
printf '%s\n' keep >"$victim/sentinel"
ln -s "$victim" "$work/state-link"
if HOOSHIX_AGENT_OS="$os_name" \
  "$stage/uninstall.sh" --prefix "$prefix" --state-dir "$work/state-link" --service-path "$service" --no-service --purge-state >/dev/null 2>&1; then
  echo "uninstaller accepted symlink state purge" >&2; exit 1
fi
[[ "$(cat "$victim/sentinel")" == keep ]]

spec="$work/service-spec.txt"
"$prefix/hooshix-agent" service-spec --state-dir "$state" --binary "$prefix/hooshix-agent" >"$spec"
if [[ "$os_name" == linux ]]; then
  grep -q 'WantedBy=default.target' "$spec"
else
  grep -q 'com.hooshix.agent' "$spec"
fi

cat >"$work/old.go" <<'EOF'
package main
import "fmt"
func main() { fmt.Println("old-marker") }
EOF
go build -o "$prefix/hooshix-agent" "$work/old.go"

HOOSHIX_AGENT_OS="$os_name" HOOSHIX_AGENT_BINARY="$stage/hooshix-agent" \
  "$stage/install.sh" --prefix "$prefix" --state-dir "$state" --service-path "$service" --no-service
[[ -f "$prefix/hooshix-agent.previous" ]]
HOOSHIX_AGENT_OS="$os_name" \
  "$stage/install.sh" --prefix "$prefix" --state-dir "$state" --service-path "$service" --no-service --rollback
marker="$("$prefix/hooshix-agent")"
[[ "$marker" == "old-marker" ]]

HOOSHIX_AGENT_OS="$os_name" \
  "$stage/uninstall.sh" --prefix "$prefix" --state-dir "$state" --service-path "$service" --no-service --purge-state
[[ ! -e "$prefix/hooshix-agent" ]]
[[ ! -e "$state" ]]

echo "Agent clean install/rollback/uninstall smoke: PASSED ($os_name)"
