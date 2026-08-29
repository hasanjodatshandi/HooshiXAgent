#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

version="${1:-}"
out_dir="${2:-$repo_root/dist}"

if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "version must be a v-prefixed semantic version, for example v1.2.3" >&2
  exit 2
fi
if ! command -v go >/dev/null 2>&1; then
  echo "go is required" >&2
  exit 1
fi
if ! command -v zip >/dev/null 2>&1; then
  echo "zip is required" >&2
  exit 1
fi

rm -rf "$out_dir"
mkdir -p "$out_dir"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

ldflags="-s -w -X github.com/hasanjodatshandi/HooshiXAgent/internal/agent.Version=$version"

package_agent() {
  local goos="$1"
  local goarch="$2"
  local stage="$work_dir/agent-${goos}-${goarch}"
  local package_base="hooshix-agent_${version}_${goos}_${goarch}"
  mkdir -p "$stage"

  if [[ "$goos" == windows ]]; then
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags="$ldflags" -o "$stage/hooshix-agent.exe" ./cmd/agent
    cp packaging/agent/windows/Install-HooshiXAgent.ps1 "$stage/"
    cp packaging/agent/windows/Uninstall-HooshiXAgent.ps1 "$stage/"
    cp packaging/agent/README.md "$stage/README.md"
    (cd "$stage" && zip -X -q "$out_dir/${package_base}.zip" ./*)
  else
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags="$ldflags" -o "$stage/hooshix-agent" ./cmd/agent
    cp packaging/agent/unix/install.sh "$stage/install.sh"
    cp packaging/agent/unix/uninstall.sh "$stage/uninstall.sh"
    cp packaging/agent/README.md "$stage/README.md"
    chmod 755 "$stage/hooshix-agent" "$stage/install.sh" "$stage/uninstall.sh"
    tar --sort=name --mtime='UTC 2000-01-01' --owner=0 --group=0 --numeric-owner -C "$stage" -cf - . | gzip -n >"$out_dir/${package_base}.tar.gz"
  fi
}

for target in \
  linux/amd64 \
  linux/arm64 \
  darwin/amd64 \
  darwin/arm64 \
  windows/amd64 \
  windows/arm64
do
  package_agent "${target%/*}" "${target#*/}"
done

# Standalone source deployment bundle for the Docker Compose Gateway package.
gateway_stage="$work_dir/gateway-deploy"
mkdir -p "$gateway_stage/cmd" "$gateway_stage/internal" "$gateway_stage/deploy"
cp go.mod go.sum "$gateway_stage/"
cp -R cmd/gateway "$gateway_stage/cmd/"
cp -R internal/gateway internal/contractv1 "$gateway_stage/internal/"
cp -R deploy/gateway "$gateway_stage/deploy/"
printf '%s\n' "$version" >"$gateway_stage/VERSION"
find "$gateway_stage" -type d -name runtime -prune -exec rm -rf {} + 2>/dev/null || true
tar --sort=name --mtime='UTC 2000-01-01' --owner=0 --group=0 --numeric-owner -C "$gateway_stage" -cf - . | gzip -n >"$out_dir/hooshix-gateway-deploy_${version}.tar.gz"

(
  cd "$out_dir"
  find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS
)

echo "Release packages built in $out_dir"
cat "$out_dir/SHA256SUMS"
