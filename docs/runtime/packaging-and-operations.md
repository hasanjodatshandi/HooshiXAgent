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

Caddy returns `404` for public `/readyz` and `/metrics`; operators use the internal deployment network for diagnostics.

Gateway logs remain structured JSON on stderr and GatewayStatusSignal records remain JSONL on stdout. Caddy access logs are JSON. Docker log rotation is bounded by file size/count.

`deploy/gateway/diagnose.sh` reports Compose status, verified internal readiness/metrics, and recent Gateway/Caddy logs.

## Release artifacts

`scripts/release/build-release.sh <version> <output>` creates:

- six Agent platform packages;
- one self-contained Gateway deployment source bundle;
- `SHA256SUMS`.

The script uses a tag-derived version and deterministic tar/gzip metadata where applicable. The Agent version is embedded with Go linker flags.

## Signed release/provenance workflow

`.github/workflows/release.yml` runs only on version tags. It:

1. builds release packages;
2. verifies `SHA256SUMS`;
3. creates GitHub Artifact Attestations for release subjects and the checksum manifest using OIDC-backed repository identity;
4. verifies those attestations against the canonical repository identity;
5. publishes the GitHub release only after verification succeeds.

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
