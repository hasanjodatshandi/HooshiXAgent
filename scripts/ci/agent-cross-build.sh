#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

for target in \
  linux/amd64 \
  linux/arm64 \
  windows/amd64 \
  windows/arm64 \
  darwin/amd64 \
  darwin/arm64
do
  goos="${target%/*}"
  goarch="${target#*/}"
  echo "cross-building Agent ${goos}/${goarch}"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -o /dev/null ./cmd/agent
done

echo "Agent cross-platform build gate: PASSED"
