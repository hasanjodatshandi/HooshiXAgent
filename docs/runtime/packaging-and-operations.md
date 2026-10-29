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

`HooshiXAgent-Setup.exe` verifies each payload twice, because a single check is only as trustworthy as the bytes it re-reads: staged files are checked against the embedded `SHA256SUMS` before anything reaches `C:\Program Files`, and the file that is *live* in the install directory is checked against the same manifest after the rename. A mismatch aborts the install rather than letting an antivirus or filter driver substitute a recognised older build while Setup prints "done". A rollback then has to take the service out of the equation before it touches files — `service stop` only posts the request, and while the Agent process is still running it holds `hooshix-agent.exe` open, so a rename back to the previous build would fail exactly when a rollback is most needed. Setup therefore waits for SCM to report the service stopped, unregisters the service when this run created that registration (a fresh install must not leave a service pointing at a binary the rollback deletes), restores the files, and when the rollback is undoing an upgrade it re-registers the restored build if this run's `service install` had already removed the old registration — then starts it.

Clean-install CI uses temporary paths plus no-service/no-persistence mode so it can exercise install/run/upgrade/rollback/uninstall deterministically without mutating the runner account.

The forward path waits the same way the rollback does. `service stop` only posts the control request, so Setup now watches the Agent's own `service status` until SCM reports the service no longer running before it moves `hooshix-agent.exe` aside, and each commit rename is retried for up to 10 seconds while a handle is still being released or a filter driver has the file open. A failed retry leaves the staged payload untouched, so the rollback still has the bytes it needs to restore. Without that bound an upgrade that would have landed a moment later was reported as a failed install — and the uninstaller already tolerated exactly this delay, so the install path had become the strictest, least reliable half of the pair.

`agent service install` is itself a delete-then-create, and it has to wait for a different SCM signal. A deleted service is really removed only once its last handle closes, and the handle still open belongs to the Agent process this very upgrade stopped. Until that happens `OpenService` also fails — with `ERROR_SERVICE_MARKED_FOR_DELETE`, not with `ERROR_SERVICE_DOES_NOT_EXIST` — so treating *any* open failure as "the name is free" fired `CreateService` immediately, and SCM refused it with that same code. The recreate now waits for the record to be genuinely gone, and when a removal outlasts the budget it reports "still being removed by SCM, close the process holding it and run setup again" instead of failing inside `CreateService`. This was observed on a real in-place upgrade on 2026-10-12: the first attempt was refused exactly this way, and because the rollback only tried to *start* the previous build, the machine was left with no `HooshiXAgent` service at all until the install was run again.

The Windows service writes its diagnostics to `agent.log` in the machine-wide state directory, bounded at 5 MiB with one retained `agent.log.1`. Three failure rules apply there. A log that cannot be opened at all — including at service start — leaves the same writer in place with its file closed, so every later line retries the open: the tunnel runs on, and a path that becomes usable mid-upgrade starts logging again instead of staying silent for the rest of the process. While the open is failing, the write reports an error instead of claiming the bytes were written; a silently swallowed diagnostic stream removes the only record of why the Agent is misbehaving. A rotation that cannot rename keeps appending rather than dropping the line, and re-syncs its size counter to the file's real length instead of resetting it, so the rotation is retried on the very next write and lands as soon as the path frees. Growth past the bound is the accepted cost of keeping diagnostics under a persistent rotation failure; the counter tells the truth either way. The log handle is deliberately held for the life of the service: it does not join its status-writer and pairing-UI goroutines on shutdown, so closing the file earlier would race with a late log line. `rotatingFile.Close` exists for tests and for a future graceful-shutdown path, not for the running service.

On Linux and macOS there is no file to rotate: `run-service` and the pairing UI are foreground processes under `systemd --user` and a LaunchAgent, and their diagnostics go to the process's stderr, which is what those hosts capture. The same rule therefore applies to both platforms — a service run must always have a reachable diagnostic sink, and neither persistence model may install a writer that throws the log away.

`--keep-config` on uninstall preserves exactly the records a reinstall needs to reconnect without re-pairing — `config.json`, the DPAPI secret store and the `.hooshix-agent-state` ownership marker — and removes everything else in the state tree, including leftover log directories, `status.json` and the pairing capability/endpoint records that install regenerates. A state directory without the Agent's own marker is refused outright, so a misdirected path is never a recursive delete target.

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

The image build copies the tracked checkout, including `.git`, and compiles with `-buildvcs=true`, so the released binary reports its source commit (`vcs.revision`) and `vcs.modified=false` in `go version -m` instead of `mod (devel)`. A build that cannot resolve VCS metadata fails rather than shipping an unstamped binary; the builder's `git` package and the `.git` tree never reach the runtime stage. Since v0.2.3 the runtime base is `alpine:3.24.3`, digest-pinned and disclosed in `THIRD_PARTY_NOTICES`.

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

### Panel download of the installer

Since 2026-10-21 the Panel serves this installer publicly at
`/download/HooshiXAgent-Setup.exe`, from the path in `HOOSHIX_AGENT_SETUP_PATH`
(`/opt/hooshix/dist/HooshiXAgent-Setup.exe` on the production host), and the
device-approval page links to it. The link is what makes the code-based pairing
flow walkable from an empty machine: the enrollment code only exists once Setup
has been run, so a user with no Agent needs the binary before the Panel can
accept their device. Serving the artifact is not a secret — the grants are — so
the route is unauthenticated, `GET`/`HEAD` only, and answers 404 when the file
is absent rather than failing the request.

The bytes served today are `25,049,600` bytes, sha256
`473c9f7f88b481e00997f891fa4b79a706a52270e91bafe76aff6e69244ed718`, built by
the release workflow on tag `v0.2.4` (commit `0611ccb`) with
`HOOSHIX_VERSION=v0.2.4`, and confirmed by downloading it back over HTTPS and
matching that digest. Its embedded payloads are `hooshix-agent.exe`
`cadba4f03294bdad8bf55b5d12c03ac8452bf10a1d3495cf07fc460eddd9bfa0` and
`hooshix-agent-tray.exe` `2764d82f959d7a86eff3dc179a4642bd03bc92a2d3ef9cbc356c8f3c82a4afb4`,
which are exactly the two digests in the `SHA256SUMS` manifest Setup verifies
before it touches `C:\Program Files`. `go version -m` reports `go1.27.3`,
`vcs.revision=0611ccb…` and `vcs.modified=false` for all three images.

`v0.2.4` adds the supervisor fix for a half-written settings file (`#64`): a
truncated `config.json` now yields `pending_config` and waits for the write to
finish instead of exiting into an SCM restart loop. It carries the v0.2.1
embedded bilingual Agent UI (`#55`, LF fix `#56`), the tray **Restart service**
item (`#58`), and the Alpine 3.24.3 Gateway runtime base (`#54`).

The patched toolchain is the reason for this rebuild, not cosmetics:
`GO-2026-6809` / `CVE-2026-111943` in `crypto/x509` was published on 2026-10-21
against `go1.27.2`, the version every artifact here had been compiled with, and
`govulncheck` traces it into the Agent's own TLS paths
(`internal/agent/webapp/webapp.go` reaches `x509.Certificate.Verify` through
`http.Server.Serve`). `5ba29e4` raised the pin everywhere at once — the CI jobs,
the digest-pinned `golang` build stage, `scripts/ci/supply-chain.sh`, ADR-0010
and `THIRD_PARTY_NOTICES` — and every published artifact was then rebuilt from
it, including `/opt/hooshix/hooshix-gateway` on the production host and
`/download/hooshix-connect.exe`.

The first commit-pinnable Setup build was `fb3275f` (sha256
`8de28236e1e2c5a60470bee2453fb03bfd7d93986db5c84129e561d2b4831edb`, 24,731,136
bytes), served until 2026-10-22. Every build before it carried
`vcs.modified=true` because Go treats any `git status --porcelain` entry,
including an untracked directory, as uncommitted, and the server backup snapshot
sat untracked until `fb3275f` ignored it.

What this build does **not** claim: it was not produced by
`.github/workflows/release.yml`, so it has no release `SHA256SUMS` tie-in, no
SBOM entry and no Artifact Attestation, and `HOOSHIX_RELEASE_SHA256SUMS` was
therefore not consulted. It is unsigned, so the accepted Authenticode risk below
attaches to it. And the two gates that prove a distribution can actually be
installed — `scripts/ci/packaging-ops.sh` (needs `zip`, absent here) and the
service install smoke (would rewrite the machine-wide `HooshiXAgent` service on
this operator desktop) — were not run against these bytes. What was run here,
against `5ba29e4` under `go1.27.3`, is `gofmt -l`, `go vet ./...`,
`go test -count=1 ./...` and `scripts/ci/agent-cross-build.sh`; `govulncheck`
could not reach `vuln.go.dev` from this network (403) and is covered by CI.
`build-setup.ps1`'s own fail-closed resource, manifest and payload-size checks
also passed. The hosted `windows-distribution-build` job remains the gate that
proves installability.

### Connect client distribution

`hooshix-connect.exe` (from `cmd/hooshix-connect`) is the Windows GUI that turns a
Panel connect bundle into a loopback Connector session. It is deliberately **not**
part of `HooshiXAgent-Setup.exe` or any Agent archive: it runs on the machine that
*connects in*, not on the paired device, so installing it with the Agent would put
it on the wrong machine. It reaches users through the Panel's
`/download/hooshix-connect.exe` route, which serves the same file an operator
builds locally with `powershell -File scripts\build-connect.ps1`.

That script is the build gate for this binary; the runtime gate that launches it is
`scripts/ci/connect-gui-runtime.ps1`, two paragraphs below. The script regenerates the
icon resource, builds with `-H windowsgui`, and then fails closed unless the produced
image has a
`.rsrc` section (icon plus application manifest, which is what makes the window
DPI-aware and runs `asInvoker`) and a GUI subsystem value of 2. Both checks exist
because the script deletes the intermediate `.syso`, so a build that silently lost
the resources would otherwise ship a console-window app with no icon. A GUI binary
has no stderr, so every start-up failure path in the program ends in a message box
rather than a silent process exit.

The unsigned-binary risk described in "Authenticode signing status (accepted risk)"
applies to `hooshix-connect.exe` too. The release workflow builds it once in the
Windows desktop job on the exact verified release commit, preserves the script's
resource and GUI-subsystem gates, and transfers those exact bytes into `finalize`.
The client is therefore included in the release `SHA256SUMS`, per-artifact SBOM and
vulnerability scan, Artifact Attestations and published GitHub release assets.
The Panel download route should serve that attested release asset rather than a
separate local rebuild.

Beyond the artifact shape, the binary is executed by `scripts/ci/connect-gui-runtime.ps1`
on the `windows-distribution-build` CI job: it launches the built exe from a throwaway
directory, drives the real window through Win32 messages, and asserts the status line,
the empty and malformed bundle refusals, the `127.0.0.1:13389` listener appearing and
disappearing, the sealed cfg, the compact shape and the reconnect without a re-paste. It
fails closed on a non-Windows host, on a session without an interactive desktop, and when
a stray `hooshix-connect` process or an occupied tunnel port would make its observations
meaningless, and it uses a fixture bundle pointing at `wss://127.0.0.1:1/connector/v1/connect`
so it needs no Gateway, no grant and no network. It does not prove that a remote desktop
session reaches a target and it does not read pixels — see
`docs/engineering/executable-runtime-gate.md` section 7 (G2).

The GUI writes exactly one file of its own: `hooshix-connect.cfg`, beside the
executable, holding the last bundle that opened a tunnel. A connect bundle carries
the grant's bearer token, so it is a credential and is never stored as readable
text: the bundle is sealed with Windows DPAPI for the current user before it
reaches the file, which also makes the file inert on another account or machine.
It is written by rename from a temporary file in the same directory, so an
interrupted save leaves either the old bundle or the new one, never a half-written
credential, and reads are bounded to 8 KiB for the same reason the Agent's state
file is. It is not part of any archive and nothing reads it except this GUI: the
setup, the Agent and the Panel never touch it. Deleting it is the supported way to
forget a saved bundle.

## Signed release/provenance workflow

The publication path in `.github/workflows/release.yml` runs on version tags and is fail-closed around the exact tagged commit; `workflow_dispatch` exists only for non-publishing post-merge verification on `main`. The tag is resolved to a 40-hex commit and `scripts/release/verify-release-commit.py` requires a completed successful `CI` **push** run for that exact SHA on `main`, including a successful `AG-8 final security / resilience / release gate` job. A tag pointing at an unverified commit is refused before build or publish.

The workflow is privilege-separated:

1. `policy` has `contents: read` plus `actions: read` only and proves exact-commit CI eligibility;
2. `build` has `contents: read` only, builds release archives and the final Gateway image candidate, generates SPDX JSON SBOMs with digest-pinned Syft, and scans artifact SBOMs plus the Gateway image SBOM with digest-pinned Trivy; fixed High/Critical findings block the build;
3. the verified candidate is transferred through GitHub Actions artifacts with `SHA256SUMS`;
4. `attest` has `contents: read` plus only the OIDC/attestation privileges (`id-token: write`, `attestations: write`, `artifact-metadata: write`); it re-verifies checksums, creates Artifact Attestations for every checksummed subject and the manifest, and verifies repository identity;
5. only `publish` receives `contents: write`. It is job-level guarded by `if: github.event_name == 'push'`, has no OIDC or attestation-minting permission, re-verifies checksums/attestations, and then creates the GitHub release.

For post-merge verification without publishing a real release, the same workflow exposes `workflow_dispatch` on `main`. The dry-run still requires successful exact-SHA main CI, builds/scans the candidate, executes the OIDC `attest` job and repository-identity verification, while the entire `publish` job is skipped. This gives R-6 actual OIDC verification evidence without granting publication privilege to the dry-run or creating/moving a version tag.

All third-party GitHub Actions in CI/release workflows are pinned to reviewed immutable 40-character commit SHAs with the reviewed semantic version recorded in an inline comment. Release archives and executables include per-artifact SPDX JSON SBOMs. The exact scanned Gateway image is also published as `hooshix-gateway-image_<version>.tar`, with its own SPDX JSON SBOM; the image archive and every SBOM are checksummed and attested like the other release subjects.

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
- the Windows Agent service distribution runtime gate `scripts/ci/windows-service-install-smoke.ps1`, which installs, asserts, restarts and uninstalls the real distribution on an elevated Windows host. It is invoked by the `windows-distribution-build` CI job, which passes the distribution it already built via `-SetupExe`; the gate fails closed rather than skipping; its step completed green on hosted run 38344596038 on 2026-10-13, run 38352326248 the same day is the first `windows-distribution-build` job to conclude green with that step inside it, and run 38361373216 (`d08e171`) is the first fully green workflow run of the chain with the step passing inside it again (`docs/engineering/executable-runtime-gate.md` section 7, G1);
- the Windows Connect GUI runtime gate `scripts/ci/connect-gui-runtime.ps1`, also invoked by `windows-distribution-build`, which launches the real `hooshix-connect.exe` and asserts its observable window, listener, saved-bundle and teardown behaviour against a loopback-only fixture bundle. It fails closed rather than skipping, passed on the operator desktop on 2026-10-13, and the same day ran for the first time on a hosted runner, where it failed inside its own path handling rather than in the application; that is fixed, and run 38352326248 the same day passed all eight scenarios inside a green `windows-distribution-build` job, repeating inside the first fully green workflow run 38361373216 (section 7, G2);
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
