# HooshiXAgent ADR Decision Register

This register tracks every allocated Architecture Decision Record ID and whether it is current architecture authority.

Normative lifecycle and stable-ID rules are defined in `docs/governance/authority-and-adr-governance.md`.

## Current register

| ID | Title | Status | Date | Current authority | Supersedes | Superseded by | File |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ADR-0001 | Agent↔Gateway Transport | Accepted | 2026-08-29 | Yes | — | — | `docs/adr/ADR-0001-agent-gateway-transport.md` |
| ADR-0002 | Per-Device Ed25519 Identity and Key Locality | Accepted | 2026-08-29 | Yes | — | — | `docs/adr/ADR-0002-device-identity-key-locality.md` |
| ADR-0003 | External HooshiX Control Panel Integration Boundary | Accepted | 2026-08-29 | Yes | — | — | `docs/adr/ADR-0003-external-control-panel-boundary.md` |
| ADR-0004 | Caddy/TLS and Domain Edge Ownership | Accepted | 2026-08-29 | Yes | — | — | `docs/adr/ADR-0004-caddy-tls-domain-edge.md` |
| ADR-0005 | Bounded Tunnel Stream Multiplexing | Accepted | 2026-08-29 | Yes | — | — | `docs/adr/ADR-0005-bounded-stream-multiplexing.md` |
| ADR-0006 | Routing Ownership Across Control Panel, Gateway, and Agent | Accepted | 2026-08-29 | Yes | — | — | `docs/adr/ADR-0006-routing-ownership.md` |
| ADR-0007 | Protocol v1 Framing and JSON Control Encoding | Accepted | 2026-08-29 | Yes | — | — | `docs/adr/ADR-0007-protocol-v1-framing-and-json-control.md` |
| ADR-0008 | Gateway Runtime State and Ingress Model | Accepted | 2026-08-29 | Yes | — | — | `docs/adr/ADR-0008-gateway-runtime-state-and-ingress.md` |
| ADR-0009 | Edge Agent Local State, Secret Storage and Runtime Model | Accepted | 2026-08-29 | Yes | — | — | `docs/adr/ADR-0009-agent-local-state-and-runtime.md` |
| ADR-0010 | Agent Packaging, Gateway Deployment and Release Trust | Accepted | 2026-08-29 | Yes — except the clauses listed in ADR-0014 | — | ADR-0014 — Windows Agent persistence/secret trust clauses only | `docs/adr/ADR-0010-packaging-deployment-and-release-trust.md` |
| ADR-0011 | Authorized On-Demand Public TLS for Dynamic Hostnames | Accepted | 2026-08-31 | Yes | — | — | `docs/adr/ADR-0011-authorized-on-demand-public-tls.md` |
| ADR-0012 | Live External Metadata Snapshot Projection | Accepted | 2026-08-31 | Yes | — | — | `docs/adr/ADR-0012-live-external-metadata-snapshot-projection.md` |
| ADR-0013 | Clean Architecture Layering for the Tunnel Upgrade | Accepted | 2026-09-06 | Yes | — | — | `docs/adr/ADR-0013-clean-architecture-tunnel-upgrade.md` |
| ADR-0014 | Windows Agent Persistence and Secret Trust Model (LocalSystem Service) | Accepted | 2026-09-16 | Yes | ADR-0010 — Windows Agent persistence/secret trust clauses only | — | `docs/adr/ADR-0014-windows-agent-service-persistence-and-secret-trust.md` |

ADR-0010 is **partially superseded**. It remains `Accepted` and current authority for every clause except the Windows Agent persistence and secret trust clauses listed in ADR-0014's "Rollback/supersession" section (the user-scoped Windows default model, the Windows DPAPI trust-boundary claim, the rejected LocalSystem-service alternative, the "persistence specs do not cross the Windows DPAPI CurrentUser boundary" fitness function, and the future-system-wide-service compatibility sentence). Its Linux/macOS packaging, Gateway deployment, observability, and release/update trust clauses remain in force. Historical ADR-0010 text is preserved unchanged as provenance; ADR-0010 carries a supersession pointer to ADR-0014.

ADR-0014 also recorded an accepted, temporary divergence between the decided Windows distribution channel (`HooshiXAgent-Setup.exe`, the service model) and the published one. **That divergence is closed.** Rollout steps R1–R5 were executed on 2026-09-17 — the archive installer was aligned, the emitted persistence spec and the CI smoke assertion were aligned, the real Windows service install/run/restart/uninstall gate was implemented, and `HooshiXAgent-Setup.exe` was made a checksummed, SBOM-scanned and attested release subject — so the Windows zip and `HooshiXAgent-Setup.exe` now install the same service model. Rollout step R6 remains **open**: Windows binaries are still not Authenticode-signed, and the accepted unsigned-MVP risk now attaches to a published artifact. The per-step status and the residual limits (the Windows service gate is invoked by the `windows-distribution-build` CI job but has not yet produced an observed CI run, and no gate performs a literal OS reboot) are recorded in ADR-0014's "Rollout steps" section and `docs/engineering/executable-runtime-gate.md` section 7.

ADR-0015 — [Negotiated resume-proof extension](ADR-0015-negotiated-resume-proof-extension.md) — Accepted, 2026-09-17. Adds the opt-in WebSocket subprotocol boundary while retaining ADR-0007 baseline-v1 compatibility and full authentication for legacy peers.

ADR IDs are stable and monotonic. The next unused ID is `ADR-0016`; allocated IDs must never be reused or renumbered.
