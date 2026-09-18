# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities through **GitHub private vulnerability reporting**: open the repository's *Security* tab and choose *Report a vulnerability*. That creates a private advisory visible only to the maintainers.

Do not open a public issue, pull request or discussion for a suspected vulnerability, and do not include live credentials, device identities, session tokens or metadata projections in a report. If a token or key may have leaked, revoke it through the external Control Panel integration first and then report.

Please include, as far as you can:

- the affected component (Edge Agent, Tunnel Gateway, deployment/edge configuration, packaging/installers, contracts) and version or commit;
- whether the deployment was dynamic (production On-Demand TLS) or static compatibility mode;
- reproduction steps and the observable result;
- impact and any known preconditions (local access, an authorized device, a paired capability).

## Supported versions

Only the latest published release and the current `main` are supported. Pre-release/MVP builds are provided as-is; see `docs/runtime/packaging-and-operations.md` for the accepted risks recorded against them (Windows binaries, including the published desktop `HooshiXAgent-Setup.exe`, are not Authenticode-signed, so a downloaded artifact's integrity must be established by verifying the release `SHA256SUMS` and its GitHub Artifact Attestation).

## Scope notes

- The separate HooshiX Control Panel is **external** to this repository and is not implemented here; vulnerabilities in it are out of scope for this project's advisories, though reports that originate from a Gateway/Agent trust boundary are in scope.
- The trust boundaries this project owns are: public edge TLS authority (Caddy + the external permission endpoint), the authenticated Agent↔Gateway tunnel, Agent device identity and local secret state, and the installer/uninstaller privilege boundary. See `docs/engineering/security-standard.md` and `docs/runtime/security-resilience-release-gate.md`.

## Handling expectations

Reports are triaged against `docs/engineering/security-standard.md`. A fix ships through the normal release gates: the exact-commit CI run must be green, release artifacts are checksummed, SBOM-scanned and attested, and the release notes record the security-relevant change.
