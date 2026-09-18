# Agent/Gateway Packaging and Operations — AG-7

**Status:** Current packaging/operations contract (origin AG-7; reconciled through RA-4)

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

Default persistence:

- Linux: user-scoped `systemd --user`;
- macOS: user-scoped LaunchAgent;
- **Windows: the `HooshiXAgent` service, running under the LocalSystem default account**, with machine-wide Agent state at `%ProgramData%\HooshiXAgent`.

Windows is the service model, not a user-scoped logon task. This is the accepted architecture decision recorded in `docs/adr/ADR-0014-windows-agent-service-persistence-and-secret-trust.md`, which supersedes the Windows clauses of ADR-0010. The reason is operational: an edge tunnel agent must serve its loopback services on a device that may have no interactive logon session, which a logon-triggered per-user task cannot do. Windows secrets are still protected by DPAPI in the **service account's** user scope (`CRYPTPROTECT_UI_FORBIDDEN`, not machine scope), and no password-bearing service account is used. Linux and macOS state remain per-user with the ADR-0010 model unchanged.

The supported Windows distribution channel is the desktop service installer `HooshiXAgent-Setup.exe` (see "Supported Windows distribution" below), and it is a published release artifact. The archive installer `packaging/agent/windows/Install-HooshiXAgent.ps1` now installs the same service model at the same machine-wide paths: it defaults to `C:\Program Files\HooshiXAgent` and `%ProgramData%\HooshiXAgent` and persists through the Agent binary's own `service install`/`service start` (ADR-0014 rollout step R1, executed 2026-09-17), with a legacy per-user logon task removed as migration cleanup. A device must still not be left with both persistence mechanisms, which is why both the installer and the uninstaller delete any pre-existing `HooshiXAgent` scheduled task.

Installers preserve an existing binary as `.previous`. A packaged rollback operation restores that previous binary without deleting the Agent identity/config/state. Uninstall preserves state unless an explicit purge option is supplied.

Clean-install CI uses temporary paths plus no-service/no-persistence mode so it can exercise install/run/upgrade/rollback/uninstall deterministically without mutating the runner account.

## Gateway deployment package

`deploy/gateway/` is the initial Docker Compose package. It contains exactly two product services:

```text
Caddy public edge
Tunnel Gateway
```

The Gateway is not host-published. Only Caddy owns public ports 80/443.

External Control Panel integration remains a read-only metadata mount, but RA-3 makes the production/default Gateway mode the ADR-0012 live generation projection:

```text
current.json
generations/<generation>/authorizations/*.json
generations/<generation>/routes/*.json
generations/<generation>/revocations/*.json
```

Compose exposes `HOOSHIX_METADATA_MODE`, `HOOSHIX_METADATA_REFRESH_INTERVAL` and `HOOSHIX_METADATA_MAX_AGE`; defaults are `live`, `1s` and `30s`. The bootstrap creates directories only. It does not manufacture a current generation, so a deployment without a valid publisher remains alive but not ready. Explicit `HOOSHIX_METADATA_MODE=static` keeps the legacy flat snapshot solely for compatibility/test/migration use.

No Control Panel service, API, database, durable Gateway datastore, broker or cache is bundled.

### TLS topology

Caddy owns public TLS/certificate automation. RA-4 makes the production/default edge a dynamic `https://` catch-all with restricted On-Demand TLS. The global `on_demand_tls { ask ... }` permission URL is supplied by the external Control Panel integration boundary and is deny-by-default; HooshiXAgent does not implement domain ownership, endpoint CRUD or the permission service itself. `Caddyfile.static` preserves the old one-host model only as explicit compatibility/test/migration mode.

Certificate permission and routing are independent checks. A permission-approved hostname can complete TLS but still receives Gateway `404` when no current route assignment exists. An unknown/unapproved hostname must fail On-Demand TLS authorization and must not enter Caddy certificate storage. Caddy forwards accepted HTTPS traffic to the Gateway over a second verified HTTPS connection.

`bootstrap-internal-tls.sh` creates a deployment-local CA and a Gateway certificate for Docker service DNS name `gateway`. Runtime secret distribution is deliberately narrow:

- Gateway gets `gateway.crt`, `gateway.key`, and `ca.crt`;
- Caddy gets only `ca.crt`;
- `ca.key` remains host-private and is never mounted into a runtime container.

Caddy explicitly configures the upstream CA trust pool and TLS server name. `tls_insecure_skip_verify` is forbidden.

Caddy also preserves the original public `Host` header so Gateway route lookup continues to use the externally assigned public hostname rather than Docker service name. The dynamic config can therefore serve independently assigned hostnames without per-host Caddy reloads.

### R-10 runtime hardening

The two-service Compose topology remains unchanged. Gateway and Caddy run as numeric UID/GID `10001:10001`, with read-only root filesystems, `no-new-privileges`, all capabilities dropped, bounded hardened `/tmp` tmpfs mounts, and explicit 256 MiB memory / 1 CPU / 256 PID ceilings. Gateway adds no capabilities; Caddy adds only `NET_BIND_SERVICE` for public ports 80/443. The Caddy `/data` and `/config` named volumes remain its only writable persistent mounts.

Every host bind is read-only and refuses implicit source creation. The deployment CA private key remains host-only. The Gateway server private key is bind-mounted read-only only into Gateway from the host-private TLS directory; Caddy receives only `ca.crt`. Runtime acceptance inspects the actual containers to reject privilege, capability, namespace, writable-mount or resource-policy drift.

These container limits are safety ceilings, not production capacity claims. R-12 measured synthetic 100/500/1000 scenarios and deliberately retained these production limits/defaults; larger deployments require representative re-measurement rather than extrapolation.

## Operational signals

The Gateway administrative listener (`-ops-listen`, loopback inside the container, never published) exposes:

- `/healthz` — process liveness;
- `/readyz` — process/config readiness;
- `/metrics` — aggregate Prometheus text metrics.

These endpoints are intentionally absent from the public listener: a Gateway-local path registered there would shadow the tenant route for every hostname, so a tenant-hosted `/healthz` could never reach the tenant application.

Current metrics are intentionally low-cardinality and unlabeled:

```text
hooshix_gateway_agent_sessions
hooshix_gateway_active_streams
hooshix_gateway_pending_handshakes
```

Caddy returns `404` for public `/readyz` and `/metrics` on every approved hostname, so those internal signals can never be published through the public edge; `/healthz` is deliberately left as an ordinary tenant path so a tenant-hosted `/healthz` keeps working. Operators use the administrative listener for diagnostics. Gateway's Compose healthcheck uses the administrative readiness endpoint, while Caddy's own container healthcheck verifies its HTTPS edge certificate against the concatenated trust roots and accepts any HTTP response (a neutral path, not a refused one) as proof that TLS terminated and an HTTP response came back.

Gateway logs remain structured JSON on stderr and GatewayStatusSignal records remain JSONL on stdout. Caddy access logs are JSON. Docker log rotation is bounded by file size/count.

`deploy/gateway/diagnose.sh` reports Compose status, verified internal readiness/metrics, and recent Gateway/Caddy logs.

## Release artifacts

`scripts/release/build-release.sh <version> <output>` creates:

- six Agent platform packages;
- one self-contained Gateway deployment source bundle;
- `SHA256SUMS`.

The script uses a tag-derived version and deterministic tar/gzip metadata where applicable. The Agent version is embedded with Go linker flags.

Every Agent package carries its own `SHA256SUMS` next to the binary, recording that binary's digest. This is a separate file from the release-level manifest of the same name: the in-package copy is what the installers verify, the release-level copy covers every published artifact.

### Supported Windows distribution

The supported Windows distribution channel for this Agent is the desktop service installer `HooshiXAgent-Setup.exe` produced by `scripts/build-setup.ps1` from `cmd/hooshix-setup`. It is the only Windows installer that installs the accepted model recorded in ADR-0014: the `HooshiXAgent` Windows service under the LocalSystem default account, state at `%ProgramData%\HooshiXAgent`, the installer-applied state-tree ACL, and the interactive-user tray auto-start task.

`HooshiXAgent-Setup.exe` is a **published release artifact**. `.github/workflows/release.yml` builds it in a dedicated `windows-setup` job on the exact verified release commit, from the released Windows archive's own `SHA256SUMS` (`HOOSHIX_RELEASE_SHA256SUMS`) and the release's linker version, so the installer's embedded Agent binary is byte-identical to the published archive. `finalize` re-verifies that the installer embeds the released `hooshix-agent.exe` verbatim, folds it into the release `SHA256SUMS` and the SBOM/vulnerability scan of the complete candidate, and `attest`/`publish` cover it as a first-class subject alongside the six platform archives. This is ADR-0014 rollout step R5, executed 2026-09-17: the decided Windows channel and the published Windows channel are now the same one.

The clean-checkout `Windows desktop distribution build / service install gate (setup + tray)` CI job still builds the distribution from a fresh checkout with no manual resource steps — it proves that, not that a release artifact was produced. It no longer stops at build integrity: it now invokes the real service install gate below, so the job also proves the built distribution can be installed, started, restarted and uninstalled on Windows.

The archive `hooshix-agent_<version>_windows_<arch>.zip` with `Install-HooshiXAgent.ps1` remains published and is built, SBOM-scanned, checksummed and attested by the same release workflow. It is no longer a divergent channel: since rollout step R1 it installs the same `HooshiXAgent` service model at the same machine-wide paths, and uninstalls it the same way. What the zip still does not provide is the desktop distribution's tray binary, `uninstall.exe` and ARP entry, which is why `HooshiXAgent-Setup.exe` is the supported channel for a Windows desktop device.

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

### Install-time checksum verification

Every installer verifies the Agent binary it is about to promote against the `SHA256SUMS` shipped inside its package, and fails closed (non-zero exit, nothing replaced) when the manifest is missing, has no entry for the binary, or the digest does not match:

- `packaging/agent/unix/install.sh` (`--checksums <path>` or `HOOSHIX_AGENT_CHECKSUMS` override the default lookup next to the script);
- `packaging/agent/windows/Install-HooshiXAgent.ps1` (`-Checksums <path>` or `HOOSHIX_AGENT_CHECKSUMS`);
- `cmd/hooshix-setup` verifies each embedded payload binary against the `SHA256SUMS` embedded alongside it in the same distribution build.

`scripts/build-setup.ps1` also verifies its payload against a release `SHA256SUMS` when `HOOSHIX_RELEASE_SHA256SUMS` points at one, which ties a locally built Setup.exe to the exact released agent binaries.

### Authenticode signing status (accepted risk)

Windows binaries are **not** Authenticode-signed. `scripts/build-setup.ps1` previously contained a signing step that silently returned unless `HOOSHIX_SIGN_CERT_PATH` was set while no workflow ever set it, so the build looked signing-capable while every produced binary was unsigned. That dormant path has been removed rather than left to imply coverage that does not exist.

The accepted risk for the unsigned MVP is: SmartScreen/AV reputation warnings and no publisher identity on the binaries; integrity is instead established by the GitHub Artifact Attestations over `SHA256SUMS` (see above), which a consumer must verify explicitly. Since ADR-0014 rollout step R5 this risk attaches to a **published** artifact, `HooshiXAgent-Setup.exe`, not only to a local build. This risk is accepted only for the pre-launch MVP and must be revisited before general availability. Adding Authenticode signing later means obtaining a code-signing certificate, adding the signing step to both `scripts/build-setup.ps1` and `.github/workflows/release.yml`, and gating the release path so a missing certificate fails the release instead of being skipped.

The Agent does not autonomously fetch or apply an update. Promotion remains explicit through verified packages. AG-8 release acceptance now covers forced network interruption/recovery, bounded exhaustion cases, update-candidate validation, previous-binary rollback, checksum tamper rejection and release-security evidence.

## Automated gates

The current packaging/operations gate provides:

- platform clean Agent install/rollback/uninstall smoke tests on Ubuntu, macOS and Windows;
- a blocking packaging/operations CI job;
- deterministic release archive/checksum construction, including the published Windows `HooshiXAgent-Setup.exe` release subject;
- the Windows Agent service distribution runtime gate `scripts/ci/windows-service-install-smoke.ps1`, which installs, asserts, restarts and uninstalls the real distribution on an elevated Windows host. It is invoked by the `windows-distribution-build` CI job, which passes the distribution it already built via `-SetupExe`; the gate fails closed rather than skipping, and its CI evidence is pending the next Windows CI run (`docs/engineering/executable-runtime-gate.md` section 7, G1);
- a clean Docker Compose Gateway+Caddy deployment test;
- RA-4 real Compose/Caddy multi-host acceptance with two simultaneous hostnames, approved-without-route separation and unknown-host TLS denial;
- real Caddy→Gateway verified TLS;
- public/private operational endpoint checks;
- release-attestation workflow trust checks.

All existing Go quality, architecture, security, executable runtime and Agent↔Gateway E2E gates remain blocking.

## R-6 dependency and image pin maintenance

Runtime/build container references keep a human-readable tag and an immutable manifest-list digest. The Gateway runtime image also pins the OpenSSL runtime packages to the fixed versions required by the R-6 vulnerability gate when the pinned Alpine base contains a known fixed High-severity issue. Current pinned references cover the Go build image, Alpine runtime base and Caddy public edge; Syft/Trivy scanner containers are also version+digest pinned inside the R-6 scripts. `scripts/ci/supply-chain.sh` rejects missing/mutable image and Action pins.

To update an Action pin, resolve the reviewed semantic tag directly from the upstream Git repository, record the dereferenced 40-hex commit in the workflow, keep the version comment, review upstream release notes/diff, and run the full R-6 plus existing release gates. To update a container base/scanner, select an explicit reviewed tag, resolve its multi-platform digest with `docker buildx imagetools inspect`, update tag and digest together, rebuild the Gateway candidate, regenerate SBOMs and rerun Trivy. Never update a digest without also reviewing what tag/content it represents.

Rollback never bypasses release eligibility. Operators may roll back to an earlier already checksummed/attested verified release. If a new fixed release is required, create a new version tag on a commit that has independently passed the exact-main CI policy; do not move/reuse a published version tag to evade the gate.
