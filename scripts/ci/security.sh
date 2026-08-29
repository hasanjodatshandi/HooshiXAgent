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

if [[ ! -f .gitleaks.toml ]]; then
  echo "required Gitleaks configuration missing: .gitleaks.toml" >&2
  exit 1
fi

gitleaks git --config .gitleaks.toml --redact --no-banner .
gitleaks dir --config .gitleaks.toml --redact --no-banner .
semgrep scan --config .semgrep.yml --error --metrics=off .

echo "Secret/static security baseline: PASSED"
