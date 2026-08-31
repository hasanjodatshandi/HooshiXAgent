# Agent/Gateway Packaging and Operations — AG-7

**Status:** Current AG-7 packaging/operations contract

AG-7 packages and operates the existing Edge Agent and Tunnel Gateway. It does not add the separate HooshiX Control Panel, a Control Panel database, tenant/user management, quotas, billing, Kubernetes, Redis or unrelated infrastructure.

## Edge Agent packages

Release artifacts are produced for:

```text
linux/amd64
linux/arm64
darwin/amd64
darwin/arm64
windows/amd64
windows/arm64
```

Linux/macOS packages are `.tar.gz`; Windows packages are `.zip`. Each package contains the real Agent executable, platform installer/uninstaller tooling and package documentation.

Default persistence is user-scoped:

- Linux: `systemd --user`;
- macOS: LaunchAgent;
- Windows: current-user logon Scheduled Task.

This is intentional: Windows Agent secrets use DPAPI CurrentUser and Unix Agent state is per-user. AG-7 does not change that trust boundary.

Installers preserve an existing binary as `.previous`. A packaged rollback operation restores that previous binary without deleting the Agent identity/config/state. Uninstall preserves state unless an explicit purge option is supplied.

Clean-install CI uses temporary paths plus no-service/no-persistence mode so it can exercise install/run/upgrade/rollback/uninstall deterministically without mutating the runner account.

## Gateway deployment package

`deploy/gateway/` is the initial Docker Compose package. It contains exactly two product services:

```text
Caddy public edge
Tunnel Gateway
```

The Gateway is not host-published. Only Caddy owns public ports 80/443.

External Control Panel integration remains a read-only metadata snapshot mount:

```text
authorizations/*.json
routes/*.json
revocations/*.json
```

No Control Panel service or database is bundled.

### TLS topology

Caddy owns public TLS/certificate automation. Caddy forwards to the Gateway over a second verified HTTPS connection.

`bootstrap-internal-tls.sh` creates a deployment-local CA and a Gateway certificate for Docker service DNS name `gateway`. Runtime secret distribution is deliberately narrow:

- Gateway gets `gateway.crt`, `gateway.key`, and `ca.crt`;
- Caddy gets only `ca.crt`;
- `ca.key` remains host-private and is never mounted into a runtime container.

Caddy explicitly configures the upstream CA trust pool and TLS server name. `tls_insecure_skip_verify` is forbidden.

Caddy also preserves the original public `Host` header so Gateway route lookup continues to use the externally assigned public hostname rather than Docker service name.

### R-10 runtime hardening

The two-service Compose topology remains unchanged. Gateway and Caddy run as numeric UID/GID `10001:10001`, with read-only root filesystems, `no-new-privileges`, all capabilities dropped, bounded hardened `/tmp` tmpfs mounts, and explicit 256 MiB memory / 1 CPU / 256 PID ceilings. Gateway adds no capabilities; Caddy adds only `NET_BIND_SERVICE` for public ports 80/443. The Caddy `/data` and `/config` named volumes remain its only writable persistent mounts.

Every host bind is read-only and refuses implicit source creation. The deployment CA private key remains host-only. The Gateway server private key is bind-mounted read-only only into Gateway from the host-private TLS directory; Caddy receives only `ca.crt`. Runtime acceptance inspects the actual containers to reject privilege, capability, namespace, writable-mount or resource-policy drift.

These container limits are safety ceilings, not production capacity claims. Evidence-based throughput/capacity tuning remains R-12 work.

## Operational signals

The Gateway internal listener exposes:

- `/healthz` — process liveness;
- `/readyz` — process/config readiness;
- `/metrics` — aggregate Prometheus text metrics.

Current metrics are intentionally low-cardinality and unlabeled:

```text
hooshix_gateway_agent_sessions
hooshix_gateway_active_streams
hooshix_gateway_pending_handshakes
```

Caddy returns `404` for public `/readyz` and `/metrics`; operators use the internal deployment network for diagnostics. Gateway's Compose healthcheck and Caddy's active upstream health probe both use `/readyz`, while Caddy's own container healthcheck exercises its local HTTPS edge path.

Gateway logs remain structured JSON on stderr and GatewayStatusSignal records remain JSONL on stdout. Caddy access logs are JSON. Docker log rotation is bounded by file size/count.

`deploy/gateway/diagnose.sh` reports Compose status, verified internal readiness/metrics, and recent Gateway/Caddy logs.

## Release artifacts

`scripts/release/build-release.sh <version> <output>` creates:

- six Agent platform packages;
- one self-contained Gateway deployment source bundle;
- `SHA256SUMS`.

The script uses a tag-derived version and deterministic tar/gzip metadata where applicable. The Agent version is embedded with Go linker flags.

## Signed release/provenance workflow

The publication path in `.github/workflows/release.yml` runs on version tags and is fail-closed around the exact tagged commit; `workflow_dispatch` exists only for non-publishing post-merge verification on `main`. The tag is resolved to a 40-hex commit and `scripts/release/verify-release-commit.py` requires a completed successful `CI` **push** run for that exact SHA on `main`, including a successful `AG-8 final security / resilience / release gate` job. A tag pointing at an unverified commit is refused before build or publish.

The workflow is privilege-separated:

1. `policy` has `contents: read` plus `actions: read` only and proves exact-commit CI eligibility;
2. `build` has `contents: read` only, builds release archives and the final Gateway image candidate, generates SPDX JSON SBOMs with digest-pinned Syft, and scans artifact SBOMs plus the Gateway image SBOM with digest-pinned Trivy; fixed High/Critical findings block the build;
3. the verified candidate is transferred through GitHub Actions artifacts with `SHA256SUMS`;
4. `attest` has `contents: read` plus only the OIDC/attestation privileges (`id-token: write`, `attestations: write`, `artifact-metadata: write`); it re-verifies checksums, creates Artifact Attestations for every checksummed subject and the manifest, and verifies repository identity;
5. only `publish` receives `contents: write`. It is job-level guarded by `if: github.event_name == 'push'`, has no OIDC or attestation-minting permission, re-verifies checksums/attestations, and then creates the GitHub release.

For post-merge verification without publishing a real release, the same workflow exposes `workflow_dispatch` on `main`. The dry-run still requires successful exact-SHA main CI, builds/scans the candidate, executes the OIDC `attest` job and repository-identity verification, while the entire `publish` job is skipped. This gives R-6 actual OIDC verification evidence without granting publication privilege to the dry-run or creating/moving a version tag.

All third-party GitHub Actions in CI/release workflows are pinned to reviewed immutable 40-character commit SHAs with the reviewed semantic version recorded in an inline comment. Release archives include per-artifact SPDX JSON SBOMs and an SPDX JSON SBOM for the built Gateway image candidate; these SBOMs are themselves checksummed and attested.

Operators verify a downloaded release before promotion:

```bash
sha256sum -c SHA256SUMS
gh attestation verify <artifact> -R hasanjodatshandi/HooshiXAgent
gh attestation verify SHA256SUMS -R hasanjodatshandi/HooshiXAgent
```

An attestation proves provenance/identity; it does not replace vulnerability, security, runtime or release acceptance gates.

The Agent does not autonomously fetch or apply an update in AG-7. Promotion remains explicit through verified packages. Final network interruption, exhaustion, update/rollback and release-security acceptance remains AG-8.

## Automated gates

AG-7 adds:

- platform clean Agent install/rollback/uninstall smoke tests on Ubuntu, macOS and Windows;
- a blocking packaging/operations CI job;
- deterministic release archive/checksum construction;
- a clean Docker Compose Gateway+Caddy deployment test;
- real Caddy→Gateway verified TLS;
- public/private operational endpoint checks;
- release-attestation workflow trust checks.

All existing Go quality, architecture, security, executable runtime and Agent↔Gateway E2E gates remain blocking.

## R-6 dependency and image pin maintenance

Runtime/build container references keep a human-readable tag and an immutable manifest-list digest. The Gateway runtime image also pins the OpenSSL runtime packages to the fixed versions required by the R-6 vulnerability gate when the pinned Alpine base contains a known fixed High-severity issue. Current pinned references cover the Go build image, Alpine runtime base and Caddy public edge; Syft/Trivy scanner containers are also version+digest pinned inside the R-6 scripts. `scripts/ci/supply-chain.sh` rejects missing/mutable image and Action pins.

To update an Action pin, resolve the reviewed semantic tag directly from the upstream Git repository, record the dereferenced 40-hex commit in the workflow, keep the version comment, review upstream release notes/diff, and run the full R-6 plus existing release gates. To update a container base/scanner, select an explicit reviewed tag, resolve its multi-platform digest with `docker buildx imagetools inspect`, update tag and digest together, rebuild the Gateway candidate, regenerate SBOMs and rerun Trivy. Never update a digest without also reviewing what tag/content it represents.

Rollback never bypasses release eligibility. Operators may roll back to an earlier already checksummed/attested verified release. If a new fixed release is required, create a new version tag on a commit that has independently passed the exact-main CI policy; do not move/reuse a published version tag to evade the gate.
