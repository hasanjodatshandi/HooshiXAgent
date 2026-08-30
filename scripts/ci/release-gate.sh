#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

for tool in go sha256sum tar unzip zip; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required AG-8 release-gate tool not found: $tool" >&2
    exit 1
  fi
done

# Final scope lock: release acceptance must not silently introduce the external Control Panel.
if find . -type d \( -name control-panel -o -name control_panel -o -name controlplane -o -name control-plane -o -name tenants -o -name users -o -name quotas -o -name billing -o -name migrations \) -not -path './.git/*' | grep -q .; then
  echo "AG-8 release gate found an out-of-scope implementation directory" >&2
  exit 1
fi

# Agent SSRF/local-target, secret storage, argument/token and update candidate security.
go test -count=1 ./internal/agent -run 'Test(LocalTargetPolicy|ReleaseLocalTargetPolicyAdversarialCases|IdentityPersistsAndSecretStateIsProtected|SecretStoreRejectsUnsafePermissionsAndSymlink|CLIStatusDoesNotLeakSecrets|GatewayURLValidation|UpdateFoundationValidation|ReleaseUpdateCandidateFailsClosed)$'

# Language-neutral frame/control strictness, replay resistance, wrap rejection, raw-target rejection and strict schemas.
go test -count=1 ./internal/contractv1 -run 'Test(FrameRejectsMalformedAndOversizedInput|SequenceTrackerRejectsReplayAndReordering|SequenceTrackerRequiresFirstSequenceOneAndRejectsWrap|ProtocolSequenceGapRejected|ProtocolInvalidUTF8Rejected|ProtocolDuplicateJSONKeysRejected|StrictJSONRejectsNestedAndEscapedDuplicateKeys|ExternalContractRejectsExpiredAuthorizationAndRawLocalTarget|ControlPayloadScopeAndStrictness|LanguageNeutralSchemaRejectsRawLocalTarget)$'

# Gateway auth/TLS/replay, exact sequence/control parsing, request/stream limits, malformed protocol and pending-handshake exhaustion.
go test -count=1 ./internal/gateway -run 'Test(GatewayRejectsUntrustedTLSInvalidTokenAndReplay|GatewayRejectsAuthenticatedProtocolStrictnessViolations|GatewaySequenceExhaustionTerminatesSession|GatewayRequestAndStreamLimits|GatewayRejectsMalformedProtocolAndHandshakeExhaustion)$'

# R-2 strict protocol gate includes authenticated negatives plus bounded fuzz smoke.
bash scripts/ci/protocol-strictness.sh

# R-3 resource/DoS gate enforces byte budgets, rate/concurrency caps and saturation metrics.
bash scripts/ci/resource-dos.sh

# R-4 streaming ingress gate proves bounded public→Agent request forwarding and cancellation.
bash scripts/ci/streaming-ingress.sh

# R-5 HTTP/stream isolation gate proves per-stream fault isolation and proxy correctness.
bash scripts/ci/http-proxy-correctness.sh

# R-7 metadata gate proves strict typed snapshot loading, indexed revocations and fail-closed readiness.
bash scripts/ci/metadata-scalability.sh

# R-8 observability/writer gate proves bounded telemetry and control-priority single-writer scheduling.
bash scripts/ci/observability-writer.sh

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/release"

go build -o "$work/bin/hooshix-agent" ./cmd/agent
go build -o "$work/bin/hooshix-gateway" ./cmd/gateway
HOOSHIX_AGENT_BINARY="$work/bin/hooshix-agent" \
HOOSHIX_GATEWAY_BINARY="$work/bin/hooshix-gateway" \
  go test -count=1 -timeout=60s ./internal/runtimegate -run '^TestNetworkInterruptionAndColdRestartRecovery$'

# Build the exact release artifact shapes and verify the manifest before any tamper test.
bash scripts/release/build-release.sh v0.0.0-ag8 "$work/release"
(
  cd "$work/release"
  sha256sum -c SHA256SUMS
)

# Release bundles must not contain repository history, runtime secret material, or Control Panel implementation.
while IFS= read -r archive; do
  case "$archive" in
    *.tar.gz) listing="$(tar -tzf "$archive")" ;;
    *.zip) listing="$(unzip -Z1 "$archive")" ;;
    *) continue ;;
  esac
  if grep -qiE '(^|/)(\.git|runtime/tls/ca\.key|control[-_]?panel|controlplane|tenants?|users?|quotas?|billing|migrations)(/|$)' <<<"$listing"; then
    echo "forbidden release artifact content found in $(basename "$archive")" >&2
    printf '%s\n' "$listing" >&2
    exit 1
  fi
done < <(find "$work/release" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' \) -print | sort)

# A modified artifact must fail checksum verification.
probe="$(find "$work/release" -maxdepth 1 -type f -name 'hooshix-agent_*_linux_amd64.tar.gz' | head -n1)"
if [[ -z "$probe" ]]; then
  echo "Linux amd64 release probe missing" >&2
  exit 1
fi
printf 'tamper' >> "$probe"
if (cd "$work/release" && sha256sum -c SHA256SUMS >/dev/null 2>&1); then
  echo "tampered release artifact unexpectedly passed SHA-256 verification" >&2
  exit 1
fi

# Signing/provenance workflow must remain OIDC-backed and verify identity before publishing.
grep -q 'id-token: write' .github/workflows/release.yml
grep -q 'attestations: write' .github/workflows/release.yml
grep -Eq 'uses: actions/attest@[0-9a-f]{40} # v4\.' .github/workflows/release.yml
grep -q 'gh attestation verify' .github/workflows/release.yml
grep -q 'verify-release-commit.py' .github/workflows/release.yml
grep -q 'supply-chain-artifacts.sh' .github/workflows/release.yml

# This final job is intentionally chained behind all prerequisite CI jobs in ci.yml.
grep -q 'name: AG-8 final security / resilience / release gate' .github/workflows/ci.yml
grep -q 'needs:' .github/workflows/ci.yml

if [[ -n "${HOOSHIX_RELEASE_EVIDENCE_DIR:-}" ]]; then
  mkdir -p "$HOOSHIX_RELEASE_EVIDENCE_DIR"
  cat >"$HOOSHIX_RELEASE_EVIDENCE_DIR/AG8-EVIDENCE.txt" <<EOF
HooshiXAgent AG-8 final release-gate evidence
commit=${GITHUB_SHA:-$(git rev-parse HEAD)}
agent_ssrf_secret_update=Passed
protocol_malformed_replay_contract=Passed
gateway_auth_replay_resource_exhaustion=Passed
network_interruption_reconnect_cold_restart=Passed
artifact_checksum_tamper=Passed
artifact_scope_secret_content=Passed
release_attestation_workflow=Passed
supply_chain_gate=required-by-needs
metadata_scalability_gate=Passed
observability_writer_gate=Passed
prerequisite_ci_jobs=required-by-needs
control_panel_scope=Not applicable (external project)
EOF
fi

echo "AG-8 final release gate: PASSED — Agent/Gateway security, malformed/replay/resource controls, network interruption recovery, cold restart persistence, artifact tamper rejection and release provenance policy were exercised."
