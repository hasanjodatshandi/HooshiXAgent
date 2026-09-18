#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

# Inspect delivery source, including new untracked source, but not ignored
# operator probes, nested external projects or generated build directories.
# Tracked files remain included even if a later ignore rule matches them.
mapfile -d '' -t source_files < <(git ls-files --cached --others --exclude-standard -z -- '*.go')
runnable_files=()
for file in "${source_files[@]}"; do
  if [[ -f "$file" ]] && grep -q '^package main$' "$file"; then
    runnable_files+=("./$file")
  fi
done
if ((${#runnable_files[@]} == 0)); then
  echo "Executable Runtime Gate: Not applicable — current repository state introduces no runnable product capability."
  exit 0
fi

if ! command -v go >/dev/null 2>&1; then
  echo "required runtime-gate tool not found: go" >&2
  exit 1
fi

source "$repo_root/scripts/ci/test-guard.sh"

unexpected=()
for file in "${runnable_files[@]}"; do
  case "$file" in
    ./cmd/gateway/*.go|./cmd/agent/*.go) ;;
    # Windows-only product executables. Their runtime procedure lives on the
    # Windows CI leg, not here: scripts/ci/windows-service-install-smoke.ps1 is
    # invoked by the windows-distribution-build job in
    # .github/workflows/ci.yml, which installs the real Setup.exe distribution,
    # asserts the accepted ADR-0014 persistence model, exercises SCM
    # restart-on-failure and asserts uninstall removes everything again. They
    # are allowlisted in this Unix gate only because Setup.exe, the LocalSystem
    # SCM service and the desktop tray cannot be exercised on Linux/macOS: they
    # stay here so this gate still executes the Gateway and Edge Agent runtime
    # the allowlisted files sit beside. The gate status is recorded in
    # docs/engineering/executable-runtime-gate.md section 7 (G1). Do not read
    # this allowlist as a statement that no runtime procedure exists.
    ./cmd/hooshix-agent-tray/*.go|./cmd/hooshix-setup/*.go) ;;
    *) unexpected+=("$file") ;;
  esac
done
if ((${#unexpected[@]} != 0)); then
  echo "runnable capability lacks an approved executable runtime procedure:" >&2
  printf '  %s\n' "${unexpected[@]}" >&2
  exit 1
fi

runtime_dir="$(mktemp -d)"
trap 'rm -rf "$runtime_dir"' EXIT

gateway_binary="$runtime_dir/hooshix-gateway${bin_suffix}"
agent_binary="$runtime_dir/hooshix-agent${bin_suffix}"
go build -o "$gateway_binary" ./cmd/gateway
go build -o "$agent_binary" ./cmd/agent

HOOSHIX_GATEWAY_BINARY="$gateway_binary" \
  fail_if_no_tests ./internal/gateway -run 'TestExternalProcessRuntimeGate|TestExecutableRefusesPlaintextStartup'

HOOSHIX_GATEWAY_BINARY="$gateway_binary" \
HOOSHIX_AGENT_BINARY="$agent_binary" \
  fail_if_no_tests ./tests/integration -run TestRealAgentGatewayRuntime

echo "Executable Runtime Gate: PASSED — real Gateway and Edge Agent processes exercised over TLS/WSS with authenticated tunnel ingress, Agent state persistence/reconnect, and plaintext-startup rejection."
