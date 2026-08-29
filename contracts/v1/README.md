# HooshiXAgent Contract Set v1

This directory is the language-neutral contract authority introduced by Durable Plan leaf AG-3.

It contains only contracts required for Edge Agent↔Tunnel Gateway operation and the minimum integration boundary with the separate HooshiX Control Panel project.

## Contents

- `tunnel-protocol.md` — normative Agent↔Gateway frame/session/stream semantics.
- `tunnel-control.schema.json` — JSON Schema 2020-12 for v1 control payloads.
- `external-control-panel-contract.md` — normative semantics for the external Control Panel boundary.
- `external/device-session-authorization.schema.json` — externally issued authorization metadata consumed by the Gateway.
- `external/endpoint-route-assignment.schema.json` — externally managed endpoint→device/local-endpoint routing metadata.
- `external/revocation-signal.schema.json` — revocation/disable signal shape.
- `external/gateway-status-signal.schema.json` — bounded operational/traffic status signal emitted by the Gateway.
- `fixtures/` — deterministic valid and invalid examples used by contract tests.

## Authority and ownership

These files do **not** implement the HooshiX Control Panel. They do not define users, tenants, plans, billing, quotas, dashboard models, database schemas, CRUD APIs, or Control Panel persistence.

The Control Panel remains the durable authority for device/session authorization and public endpoint assignments. The Gateway consumes validated copies of the external records. The Agent receives only the information necessary to authenticate and to resolve an externally assigned endpoint to a locally approved `local_endpoint_id`.

No contract in this directory may contain an arbitrary local IP address, URL, file path, Unix socket, named pipe, or other raw Agent target selected by the Gateway or public caller.

## Versioning

`v1` is wire/contract version 1. Incompatible changes require a new version directory and the applicable ADR/change-control process. Unknown versions are rejected rather than guessed.
