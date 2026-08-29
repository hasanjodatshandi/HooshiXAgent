#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

mapfile -t runnable_files < <(grep -RIl --include='*.go' --exclude-dir='.git' '^package main$' . 2>/dev/null | sort || true)
if ((${#runnable_files[@]} != 0)); then
  echo "runnable Go capability detected:" >&2
  printf '  %s\n' "${runnable_files[@]}" >&2
  echo "The AG-2 baseline runtime gate is fail-closed. The leaf that introduces a runnable capability must replace or extend this guard with the real Executable Runtime Gate required by docs/engineering/executable-runtime-gate.md." >&2
  exit 1
fi

echo "Executable Runtime Gate: Not applicable — current repository state introduces no runnable product capability."
