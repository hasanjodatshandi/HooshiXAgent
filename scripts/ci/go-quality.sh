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

mapfile -t go_files < <(find . -type f -name '*.go' -not -path './.git/*' -print | sort)
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
trap 'rm -rf "$module_snapshot"' EXIT
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
go test -count=1 ./...
go test -race -count=1 ./...
govulncheck ./...
go build ./...

echo "Go quality/security baseline: PASSED"
