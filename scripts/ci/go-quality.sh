#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

required_tools=(go goimports govulncheck)
for tool in "${required_tools[@]}"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: $tool" >&2
    exit 1
  fi
done

version="$(go version)"
case "$version" in
  "go version go1.27."*|"go version go1.27 "*) ;;
  *)
    echo "Go 1.27.x is required; got: $version" >&2
    exit 1
    ;;
esac

mapfile -d '' -t source_files < <(git ls-files --cached --others --exclude-standard -z -- '*.go')
go_files=()
for file in "${source_files[@]}"; do
  [[ ! -f "$file" ]] || go_files+=("$file")
done
if ((${#go_files[@]} == 0)); then
  echo "no Go files found" >&2
  exit 1
fi

unformatted="$(gofmt -l "${go_files[@]}")"
if [[ -n "$unformatted" ]]; then
  echo "gofmt drift detected:" >&2
  echo "$unformatted" >&2
  exit 1
fi

import_drift="$(goimports -l "${go_files[@]}")"
if [[ -n "$import_drift" ]]; then
  echo "goimports drift detected:" >&2
  echo "$import_drift" >&2
  exit 1
fi

module_snapshot="$(mktemp -d)"
runtime_dir="$(mktemp -d)"
trap 'rm -rf "$module_snapshot" "$runtime_dir"' EXIT
cp go.mod "$module_snapshot/go.mod"
if [[ -f go.sum ]]; then
  cp go.sum "$module_snapshot/go.sum"
  touch "$module_snapshot/had-go-sum"
fi

go mod tidy
if ! cmp -s go.mod "$module_snapshot/go.mod"; then
  echo "go mod tidy changed go.mod" >&2
  exit 1
fi
if [[ -f "$module_snapshot/had-go-sum" ]]; then
  if [[ ! -f go.sum ]] || ! cmp -s go.sum "$module_snapshot/go.sum"; then
    echo "go mod tidy changed go.sum" >&2
    exit 1
  fi
elif [[ -f go.sum ]]; then
  echo "go mod tidy created go.sum" >&2
  exit 1
fi

go mod verify
go vet ./...

# tests/integration asserts real Agent↔Gateway behavior over real processes and
# fails closed in CI when the product binaries are missing. Build and export
# them here so the default `go test ./...` below actually executes those
# end-to-end assertions instead of skipping every one of them and printing ok.
# This gate must never report success without running a single tunneled request.
source "$repo_root/scripts/ci/test-guard.sh"
go build -o "$runtime_dir/hooshix-agent${bin_suffix}" ./cmd/agent
go build -o "$runtime_dir/hooshix-gateway${bin_suffix}" ./cmd/gateway
HOOSHIX_AGENT_BINARY="$runtime_dir/hooshix-agent${bin_suffix}"
HOOSHIX_GATEWAY_BINARY="$runtime_dir/hooshix-gateway${bin_suffix}"
export HOOSHIX_AGENT_BINARY HOOSHIX_GATEWAY_BINARY

go test -count=1 ./...
go test -race -count=1 ./...
govulncheck ./...
go build ./...
bash scripts/ci/agent-cross-build.sh

echo "Go quality/security baseline: PASSED"
