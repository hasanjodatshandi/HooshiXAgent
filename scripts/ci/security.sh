#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

for tool in gitleaks semgrep; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required security tool not found: $tool" >&2
    exit 1
  fi
done

gitleaks git --redact --no-banner .
gitleaks dir --redact --no-banner .
semgrep scan --config .semgrep.yml --error --metrics=off .

echo "Secret/static security baseline: PASSED"
