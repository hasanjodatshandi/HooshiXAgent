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

HOOSHIX_AGENT_OS="$os_name" HOOSHIX_AGENT_BINARY="$stage/hooshix-agent" \
  "$stage/install.sh" --prefix "$prefix" --state-dir "$state" --service-path "$service" --no-service
"$prefix/hooshix-agent" init --state-dir "$state" --json >/dev/null
"$prefix/hooshix-agent" status --state-dir "$state" --json >/dev/null

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
