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
    # cmd/hooshix-connector is executed by this very gate, not allowlisted away:
    # the binary is built below and launched as a real process by
    # TestRealConnectorExecutableCarriesPrivateTCPBytes, which drives bytes
    # through the real Agent tunnel over a Panel-shaped -bundle, rejects a
    # malformed bundle before opening any socket, and asserts the loopback port
    # is released when the process exits.
    ./cmd/hooshix-connector/*.go) ;;
    # cmd/hooshix-connect is the Windows GUI shell over that same connector. It
    # has no runtime on Linux/macOS (Win32 message loop built with
    # -H windowsgui), so it is allowlisted here rather than faked: the state
    # machine it renders is cross-platform and executed by ./internal/connectgui
    # on every OS, while the shell itself is launched as a real process by
    # scripts/ci/connect-gui-runtime.ps1 on the windows-distribution-build job
    # of .github/workflows/ci.yml: that gate drives the window through Win32 and
    # asserts the status and message lines, the empty and malformed bundle
    # refusals, the 127.0.0.1:13389 listener appearing and disappearing, the
    # sealed hooshix-connect.cfg beside the exe, the compact shape and the
    # reconnect with no re-paste. The gate status is recorded in
    # docs/engineering/executable-runtime-gate.md section 7 (G2). Do not read
    # this allowlist as a statement that no runtime procedure is required.
    ./cmd/hooshix-connect/*.go) ;;
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
connector_binary="$runtime_dir/hooshix-connector${bin_suffix}"
go build -o "$gateway_binary" ./cmd/gateway
go build -o "$agent_binary" ./cmd/agent
go build -o "$connector_binary" ./cmd/hooshix-connector

HOOSHIX_GATEWAY_BINARY="$gateway_binary" \
  fail_if_no_tests ./internal/gateway -run 'TestExternalProcessRuntimeGate|TestExecutableRefusesPlaintextStartup'

HOOSHIX_GATEWAY_BINARY="$gateway_binary" \
HOOSHIX_AGENT_BINARY="$agent_binary" \
  fail_if_no_tests ./tests/integration -run TestRealAgentGatewayRuntime

HOOSHIX_CONNECTOR_BINARY="$connector_binary" \
  fail_if_no_tests ./tests/integration -run TestRealConnectorExecutableCarriesPrivateTCPBytes

echo "Executable Runtime Gate: PASSED — real Gateway and Edge Agent processes exercised over TLS/WSS with authenticated tunnel ingress, Agent state persistence/reconnect, and plaintext-startup rejection, plus the real hooshix-connector executable carrying a private TCP flow through that tunnel from a connect bundle."
