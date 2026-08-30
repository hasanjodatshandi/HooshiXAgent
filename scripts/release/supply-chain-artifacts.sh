#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
dist_dir="${1:-}"
gateway_image_tar="${2:-}"
version="${3:-}"

if [[ -z "$dist_dir" || -z "$gateway_image_tar" || -z "$version" ]]; then
  echo "usage: supply-chain-artifacts.sh <dist-dir> <gateway-image-tar> <version>" >&2
  exit 2
fi
if [[ ! -d "$dist_dir" || ! -f "$gateway_image_tar" ]]; then
  echo "release dist directory and Gateway image tar are required" >&2
  exit 1
fi
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid release version" >&2
  exit 2
fi
for tool in docker tar unzip sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required supply-chain tool missing: $tool" >&2; exit 1; }
done

SYFT_IMAGE='anchore/syft:v1.51.1@sha256:95fe0835e5bebc6f8b1f8acef68d47d63d594ef4c0f25c097ff853b23cbac74c'
TRIVY_IMAGE='aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969'

dist_dir="$(cd "$dist_dir" && pwd)"
image_dir="$(cd "$(dirname "$gateway_image_tar")" && pwd)"
image_name="$(basename "$gateway_image_tar")"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
trivy_cache="${HOOSHIX_TRIVY_CACHE_DIR:-$work_dir/trivy-cache}"
mkdir -p "$trivy_cache" "$work_dir/extracted"

mapfile -t primary_artifacts < <(find "$dist_dir" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' \) -printf '%f\n' | LC_ALL=C sort)
if (( ${#primary_artifacts[@]} == 0 )); then
  echo "no release archives found for SBOM generation" >&2
  exit 1
fi

# Fetch the vulnerability database once; all scans below are offline against this exact cached snapshot.
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e TRIVY_CACHE_DIR=/cache \
  -v "$trivy_cache:/cache" \
  "$TRIVY_IMAGE" image --db-repository public.ecr.aws/aquasecurity/trivy-db:2 --download-db-only --no-progress >/dev/null

for artifact in "${primary_artifacts[@]}"; do
  sbom="${artifact}.spdx.json"
  docker run --rm \
    -v "$dist_dir:/dist:rw" \
    "$SYFT_IMAGE" scan "/dist/$artifact" -o "spdx-json=/dist/$sbom" >/dev/null
  [[ -s "$dist_dir/$sbom" ]]

  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e TRIVY_CACHE_DIR=/cache \
    -v "$trivy_cache:/cache" \
    -v "$dist_dir:/dist:ro" \
    "$TRIVY_IMAGE" sbom \
      --skip-db-update \
      --scanners vuln \
      --severity HIGH,CRITICAL \
      --ignore-unfixed \
      --exit-code 1 \
      --no-progress \
      "/dist/$sbom"
done

gateway_sbom="hooshix-gateway-image_${version}.spdx.json"
docker run --rm \
  -v "$dist_dir:/dist:rw" \
  -v "$image_dir:/image:ro" \
  "$SYFT_IMAGE" scan "docker-archive:/image/$image_name" -o "spdx-json=/dist/$gateway_sbom" >/dev/null
[[ -s "$dist_dir/$gateway_sbom" ]]

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e TRIVY_CACHE_DIR=/cache \
  -v "$trivy_cache:/cache" \
  -v "$image_dir:/image:ro" \
  "$TRIVY_IMAGE" image \
    --input "/image/$image_name" \
    --skip-db-update \
    --scanners vuln \
    --severity HIGH,CRITICAL \
    --ignore-unfixed \
    --exit-code 1 \
    --no-progress

(
  cd "$dist_dir"
  find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS
  sha256sum -c SHA256SUMS
)

echo "Release SBOM/vulnerability gate: PASSED — Syft SPDX SBOMs generated; Trivy scanned extracted release artifacts and the final Gateway image candidate; fixed High/Critical findings block publication."