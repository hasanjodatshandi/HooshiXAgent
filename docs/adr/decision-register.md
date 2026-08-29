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

ADR IDs are stable and monotonic. The next unused ID is `ADR-0007`; allocated IDs must never be reused or renumbered.
