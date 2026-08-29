# Shared / Integration Contract Boundary

This directory reserves the language-neutral contract boundary required by the approved HooshiXAgent architecture.

AG-2 intentionally contains **no concrete protocol schema, field layout, message encoding, API model, mock fixture, or Control Panel business contract**.

Concrete Agent↔Gateway protocol definitions and the minimum external HooshiX Control Panel integration contract belong to the later approved **AG-3 — Shared Tunnel Protocol and External Control Panel Integration Contract** leaf.

Allowed future ownership remains limited to:

- Agent↔Gateway tunnel/session protocol definitions;
- endpoint/session/routing identifiers required at runtime;
- external metadata interfaces or language-neutral schemas needed to decouple Gateway from Control Panel implementation;
- shared security/version/error semantics required by Agent and Gateway.

Users, tenants, quotas, billing, Control Panel persistence, Control Panel APIs, and UI models remain out of scope for this repository.
