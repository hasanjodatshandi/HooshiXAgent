#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

for tool in go openssl python3 zip; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required R-9 tool missing: $tool" >&2; exit 1; }
done

source "$repo_root/scripts/ci/test-guard.sh"

fail_if_no_tests ./internal/agent \
  -run 'Test(LoadConfigRejectsTrailingJSONData|ConfigFileSymlinkRejected|SecretStateRejectsTrailingAndUnknownJSON|StateMarkerAdoptsLegacyKnownStateFiles|ConcurrentConfigMutationPreservesEveryEndpoint|StateDirectorySafetyRejectsRootHomeAndSymlinks|StateDirectoryOwnershipRejectsUnrelatedNonEmptyDirectory|ConfigLockRejectsUnsafeLockObject|EntropyFailuresReturnErrorsWithoutPersistingWeakState)$'
go test -race -count=10 ./internal/agent \
  -run 'Test(LoadConfigRejectsTrailingJSONData|ConfigFileSymlinkRejected|SecretStateRejectsTrailingAndUnknownJSON|StateMarkerAdoptsLegacyKnownStateFiles|ConcurrentConfigMutationPreservesEveryEndpoint|StateDirectorySafetyRejectsRootHomeAndSymlinks|StateDirectoryOwnershipRejectsUnrelatedNonEmptyDirectory|ConfigLockRejectsUnsafeLockObject|EntropyFailuresReturnErrorsWithoutPersistingWeakState)$'

case "$(uname -s)" in
  Linux|Darwin) bash scripts/ci/agent-install-smoke.sh ;;
esac

work="$(mktemp -d)"
cleanup(){ rm -rf "$work"; }
trap cleanup EXIT

# CA bootstrap must fail closed for partial state.
mkdir -p "$work/key-only/tls"
printf '%s\n' partial >"$work/key-only/tls/ca.key"
if HOOSHIX_TLS_DIR="$work/key-only/tls" HOOSHIX_METADATA_DIR="$work/key-only/metadata" bash deploy/gateway/bootstrap-internal-tls.sh >/dev/null 2>&1; then
  echo "CA bootstrap accepted key-only partial state" >&2; exit 1
fi
[[ ! -e "$work/key-only/tls/ca.crt" ]]

mkdir -p "$work/cert-only/tls"
printf '%s\n' partial >"$work/cert-only/tls/ca.crt"
if HOOSHIX_TLS_DIR="$work/cert-only/tls" HOOSHIX_METADATA_DIR="$work/cert-only/metadata" bash deploy/gateway/bootstrap-internal-tls.sh >/dev/null 2>&1; then
  echo "CA bootstrap accepted cert-only partial state" >&2; exit 1
fi
[[ ! -e "$work/cert-only/tls/ca.key" ]]

# Failure during fresh CA generation must leave no final partial pair.
real_openssl="$(command -v openssl)"
mkdir -p "$work/fakebin" "$work/failed-generation/tls"
cat >"$work/fakebin/openssl" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == req ]]; then
  exit 77
fi
exec "$REAL_OPENSSL" "$@"
SH
chmod 755 "$work/fakebin/openssl"
if REAL_OPENSSL="$real_openssl" PATH="$work/fakebin:$PATH" \
  HOOSHIX_TLS_DIR="$work/failed-generation/tls" HOOSHIX_METADATA_DIR="$work/failed-generation/metadata" \
  bash deploy/gateway/bootstrap-internal-tls.sh >/dev/null 2>&1; then
  echo "CA bootstrap unexpectedly succeeded with failing certificate generation" >&2; exit 1
fi
[[ ! -e "$work/failed-generation/tls/ca.key" && ! -e "$work/failed-generation/tls/ca.crt" ]]

# The deployment CA must be a well-formed trust anchor, not merely a signing
# key. An extension-less CA is accepted by Go, Caddy and Schannel, but strict
# OpenSSL 3.x verification rejects it while validating any issued certificate
# ("CA cert does not include key usage extension"), so strict clients refuse the
# projected CA. Verify the CA profile and a strict verification of the Gateway
# certificate it issued.
HOOSHIX_TLS_DIR="$work/ca-profile/tls" HOOSHIX_METADATA_DIR="$work/ca-profile/metadata" \
  bash deploy/gateway/bootstrap-internal-tls.sh >/dev/null
ca_profile_cert="$work/ca-profile/tls/ca.crt"
ca_profile_text="$(openssl x509 -in "$ca_profile_cert" -noout -text)"
grep -q 'X509v3 Basic Constraints: critical' <<<"$ca_profile_text" ||
  { echo "deployment CA has no critical basicConstraints" >&2; exit 1; }
grep -q 'CA:TRUE' <<<"$ca_profile_text" ||
  { echo "deployment CA certificate is not marked as a CA" >&2; exit 1; }
grep -q 'X509v3 Key Usage: critical' <<<"$ca_profile_text" ||
  { echo "deployment CA has no critical keyUsage" >&2; exit 1; }
grep -q 'Certificate Sign' <<<"$ca_profile_text" ||
  { echo "deployment CA keyUsage omits certificate signing" >&2; exit 1; }
grep -q 'X509v3 Subject Key Identifier' <<<"$ca_profile_text" ||
  { echo "deployment CA has no subjectKeyIdentifier" >&2; exit 1; }
openssl x509 -in "$ca_profile_cert" -noout -subject |
  grep -q 'CN=HooshiX Gateway Deployment CA' ||
  { echo "deployment CA subject changed" >&2; exit 1; }
if ! openssl verify -x509_strict -CAfile "$ca_profile_cert" "$work/ca-profile/tls/gateway.crt" >/dev/null 2>&1; then
  echo "strict OpenSSL 3.x clients reject the deployment CA as a trust anchor" >&2
  openssl verify -x509_strict -CAfile "$ca_profile_cert" "$work/ca-profile/tls/gateway.crt" >&2 || true
  exit 1
fi

# Existing CA key/cert must match.
HOOSHIX_TLS_DIR="$work/mismatch/tls" HOOSHIX_METADATA_DIR="$work/mismatch/metadata" \
  bash deploy/gateway/bootstrap-internal-tls.sh >/dev/null
openssl genrsa -out "$work/mismatch/replacement.key" 3072 >/dev/null 2>&1
mv "$work/mismatch/replacement.key" "$work/mismatch/tls/ca.key"
if HOOSHIX_TLS_DIR="$work/mismatch/tls" HOOSHIX_METADATA_DIR="$work/mismatch/metadata" \
  bash deploy/gateway/bootstrap-internal-tls.sh >/dev/null 2>&1; then
  echo "CA bootstrap accepted mismatched CA key/certificate" >&2; exit 1
fi

# Release cleanup guard negatives run only inside a fake repository. This prevents a broken guard from ever deleting the real repository or filesystem root.
fake_repo="$work/fake-repo"
mkdir -p "$fake_repo/scripts/release" "$fake_repo/repo-content"
cp scripts/release/build-release.sh "$fake_repo/scripts/release/build-release.sh"
printf '%s\n' keep >"$fake_repo/repo-content/sentinel"
if bash "$fake_repo/scripts/release/build-release.sh" v0.0.0-r9 "$fake_repo" >/dev/null 2>&1; then
  echo "release builder accepted its fake repository root as output" >&2
  exit 1
fi
[[ "$(cat "$fake_repo/repo-content/sentinel")" == keep ]]

mkdir -p "$work/unowned/release"
printf '%s\n' keep >"$work/unowned/release/sentinel"
if bash "$fake_repo/scripts/release/build-release.sh" v0.0.0-r9 "$work/unowned/release" >/dev/null 2>&1; then
  echo "release builder accepted unowned non-empty output" >&2
  exit 1
fi
[[ "$(cat "$work/unowned/release/sentinel")" == keep ]]

mkdir -p "$work/fake-owned/release"
printf '%s
' keep >"$work/fake-owned/release/sentinel"
printf '%s
' hooshix-release-output-v1 >"$work/release-marker-source"
ln -s "$work/release-marker-source" "$work/fake-owned/release/.hooshix-release-output"
if bash "$fake_repo/scripts/release/build-release.sh" v0.0.0-r9 "$work/fake-owned/release" >/dev/null 2>&1; then
  echo "release builder accepted symlink ownership marker" >&2
  exit 1
fi
[[ "$(cat "$work/fake-owned/release/sentinel")" == keep ]]

mkdir -p "$work/release-victim"
printf '%s\n' keep >"$work/release-victim/sentinel"
ln -s "$work/release-victim" "$work/release-link"
if bash "$fake_repo/scripts/release/build-release.sh" v0.0.0-r9 "$work/release-link" >/dev/null 2>&1; then
  echo "release builder accepted symlink output" >&2
  exit 1
fi
[[ "$(cat "$work/release-victim/sentinel")" == keep ]]

echo "R-9 Agent state/installer hardening gate: PASSED — strict config EOF, concurrent mutation locking, state ownership/path safety, destructive cleanup guards, CA fail-closed bootstrap and entropy error paths passed."