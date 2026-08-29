# ADR-0007: Protocol v1 Framing and JSON Control Encoding

Status: Accepted
Date: 2026-08-29

## Context:

AG-3 must turn the AG-1 Agent↔Gateway protocol scope into a concrete, language-neutral contract without implementing Gateway or Agent runtime behavior. The transport is already fixed by ADR-0001 as outbound WSS/TLS over TCP 443, and ADR-0005 requires bounded logical stream multiplexing.

The contract must support authenticated session setup, replay-resistant sequencing, heartbeat, stream open/data/close/error, revocation, and strict resource bounds while remaining implementable from Go and other languages.

## Decision:

Protocol v1 uses one binary protocol frame per WebSocket binary message.

Each frame has a fixed 24-byte network-byte-order header containing:

- magic `HXT1`;
- protocol version `1`;
- frame kind (`control` or `data`);
- reserved flags;
- stream ID;
- payload length;
- monotonically increasing per-direction sequence number.

Control frames carry UTF-8 JSON objects conforming to `contracts/v1/tunnel-control.schema.json`. Data frames carry opaque raw bytes and never carry a raw local target address.

Session-level control frames use stream ID `0`. Gateway-created logical tunnel streams use non-zero stream IDs. Stream IDs are unique for the lifetime of one authenticated session and are not reused within that session.

Protocol v1 bounds are part of the contract:

- maximum control payload: 64 KiB;
- maximum data payload: 1 MiB;
- frame payload length must exactly match the header value;
- sequence numbers start at `1` and strictly increase independently in each direction;
- reserved flag bits must be zero in v1;
- unknown frame kinds, unsupported versions, malformed JSON control payloads, duplicate/replayed sequence numbers, and over-limit payloads are rejected.

The external Control Panel boundary is represented separately by JSON Schema 2020-12 contracts under `contracts/v1/external/`. Those contracts carry authorization/routing/revocation/status metadata only and do not define Control Panel CRUD APIs or persistence.

## Alternatives:

- JSON-only tunnel frames including base64 stream data: rejected because it adds avoidable encoding overhead to the data path.
- A third-party binary IDL/serialization dependency for v1: not selected because AG-3 can satisfy the required language-neutral contract with a fixed frame header, JSON control schemas, and raw data payloads without adding a serialization runtime dependency.
- Raw WebSocket messages without an explicit protocol header: rejected because protocol versioning, stream identity, payload bounds, and replay sequencing would be ambiguous.

## Consequences:

The data path stays byte-oriented while control messages remain inspectable and language-neutral. Every implementation must enforce the same fixed header and JSON control schema semantics. Later runtime leaves may optimize implementation details but cannot silently change this wire contract.

## Security impact:

Strict payload bounds, exact length checks, reserved-bit rejection, supported-version rejection, monotonic sequence enforcement, authenticated session semantics, and strict JSON field validation are mandatory. Control messages cannot carry or override arbitrary local target addresses. TLS verification and Ed25519 device-key locality remain governed by ADR-0001 and ADR-0002.

## Reliability/performance impact:

The 24-byte fixed header makes frame parsing deterministic and permits bounded multiplexing without base64 expansion for stream data. Stream/session teardown and backpressure implementation remain later runtime work but must preserve the v1 bounds.

## Compatibility/migration impact:

Wire-incompatible changes require a new protocol version and a new accepted ADR where architecturally material. Implementations must reject unsupported versions rather than guessing compatibility.

## Verification / fitness functions:

- Reference codec tests encode/decode the language-neutral frame vectors.
- Contract tests reject wrong magic/version/kind/flags/length/sequence and oversized payloads.
- JSON control fixtures validate against the documented v1 message rules.
- External authorization/routing fixtures can be consumed without any Control Panel service or database.
- No Agent or Gateway executable is introduced by AG-3.

## Rollback/supersession:

Supersession requires a new accepted ADR and any required Durable Plan change. Until then, protocol v1 framing and control encoding are current authority.

## Related ADRs:

- ADR-0001 — Agent↔Gateway transport
- ADR-0002 — per-device Ed25519 identity and key locality
- ADR-0003 — external Control Panel integration boundary
- ADR-0005 — bounded tunnel stream multiplexing
- ADR-0006 — routing ownership across Control Panel, Gateway, and Agent
