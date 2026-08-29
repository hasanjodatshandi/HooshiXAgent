# Shared / Integration Contract Boundary

This directory contains the language-neutral contracts required by the approved HooshiXAgent architecture.

Current contract authority is versioned under:

```text
contracts/v1/
```

AG-3 defines:

- Agent↔Gateway protocol-v1 framing and control-message contracts;
- device/session authorization metadata consumed from the external HooshiX Control Panel boundary;
- endpoint assignment/routing metadata;
- revocation signals;
- bounded Gateway status/traffic signals;
- deterministic valid/invalid fixtures for independent development and security validation.

The contracts remain limited to runtime integration. They do **not** implement or model Control Panel business features such as users, tenants, plans, billing, quotas, dashboards, CRUD APIs, database schemas, or migrations.

The Gateway must not use a Control Panel database as direct authority. A public caller or Gateway message must not provide an arbitrary Agent-local target; route contracts contain only an opaque `local_endpoint_id`, which the Agent resolves against its own approved local mapping and security policy.
