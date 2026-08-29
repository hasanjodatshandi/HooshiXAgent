# HooshiXAgent Tunnel Protocol v1

**Status:** Normative
**Transport:** WebSocket Secure over TLS on TCP 443
**WebSocket message type:** binary

This specification defines the concrete language-neutral Agent↔Gateway wire contract required by AG-3. It does not implement the Gateway or Agent runtime.

## 1. Frame layout

Each WebSocket binary message contains exactly one HooshiXAgent frame.

The fixed header is 24 bytes, network byte order (big-endian):

| Offset | Size | Field | v1 rule |
| ---: | ---: | --- | --- |
| 0 | 4 | Magic | ASCII `HXT1` |
| 4 | 1 | Version | `0x01` |
| 5 | 1 | Kind | `0x01` control, `0x02` data |
| 6 | 2 | Flags | `0x0000` in v1 |
| 8 | 4 | Stream ID | `0` for session control; non-zero for stream scope |
| 12 | 4 | Payload length | Exact payload byte count |
| 16 | 8 | Sequence | Starts at `1`; strictly increases per direction |

A receiver rejects a frame before payload processing when magic, version, kind, flags, payload length, or sequence semantics are invalid.

## 2. Bounds

Protocol v1 uses these hard contract bounds:

```text
maximum control payload = 65,536 bytes
maximum data payload    = 1,048,576 bytes
```

The WebSocket message must contain exactly `24 + payload_length` bytes.

Implementations may enforce lower operational limits through configuration, but may not accept frames above the v1 contract maximum.

## 3. Sequence / replay rule

Each direction has an independent unsigned 64-bit sequence space.

- first frame sent after WebSocket establishment uses sequence `1`;
- each subsequent frame increments the sequence;
- a receiver rejects a sequence less than or equal to the last accepted sequence;
- sequence wrap is not permitted; the session must terminate before wrap.

TLS protects transport confidentiality/integrity. The protocol sequence is an additional replay/order invariant within the authenticated tunnel session; it is not a replacement for TLS or authentication.

## 4. Stream IDs

Session-level control uses stream ID `0`.

For v1 public-ingress tunnel flows:

- the Gateway allocates a non-zero stream ID;
- a stream ID is unique for one authenticated Agent session;
- a stream ID is not reused during that session after close/error;
- `stream_open`, `stream_close`, `stream_error`, and data frames are stream-scoped;
- data on an unknown/not-open/already-closed stream is rejected.

## 5. Control payload encoding

Control payloads are UTF-8 JSON objects and must satisfy `tunnel-control.schema.json` plus the semantic rules below.

Unknown fields are rejected. Strings are length-bounded by the schema. Identifiers are opaque and must match the schema identifier pattern; implementations must not infer account, tenant, billing, or database semantics from them.

## 6. Session establishment

The v1 handshake is:

```text
Agent   -> Gateway : client_hello      (stream 0)
Gateway -> Agent   : server_challenge  (stream 0)
Agent   -> Gateway : client_auth       (stream 0)
Gateway -> Agent   : session_ready     (stream 0)
```

### client_hello

The Agent sends:

- `device_id` — opaque externally registered device identifier;
- `authorization_id` — authorization record identifier;
- `token_id` — identifier for the short-lived opaque token;
- `session_token` — opaque token value issued externally;
- `client_nonce` — 32 random bytes encoded base64url without padding.

The Gateway validates the token against the externally supplied `device-session-authorization` contract. The raw token is never persisted or logged by this contract.

### server_challenge

After a valid authorization lookup, the Gateway sends:

- `session_id` — fresh opaque session identifier;
- `server_nonce` — 32 random bytes base64url without padding;
- `expires_at` — RFC3339 UTC expiration for completing authentication.

### client_auth

The Agent signs this exact byte sequence using its device Ed25519 private key:

```text
HXT1-AUTH\x00
|| session_id || \x00
|| device_id || \x00
|| authorization_id || \x00
|| token_id || \x00
|| client_nonce || \x00
|| server_nonce
```

Every identifier and nonce is encoded as its UTF-8 representation exactly as present in the validated control messages. Contract identifier patterns prohibit NUL bytes, making the delimiter unambiguous.

`client_auth.signature` is the 64-byte Ed25519 signature encoded base64url without padding.

The Gateway verifies the signature using `device_public_key` from the matching external authorization record.

### session_ready

On successful authentication, the Gateway confirms:

- `session_id`;
- `heartbeat_interval_seconds`;
- `idle_timeout_seconds`.

Protocol v1 contract bounds require:

```text
heartbeat_interval_seconds: 5..60
idle_timeout_seconds:       15..300
idle_timeout_seconds >= 2 * heartbeat_interval_seconds
```

Exact runtime defaults are chosen by the later Gateway implementation within these bounds.

Authentication failure terminates the WebSocket session without an insecure fallback.

## 7. Heartbeat

`ping` and `pong` are session-level control messages on stream ID `0`.

- `ping` contains an opaque `ping_id` and sender timestamp.
- `pong` echoes the same `ping_id` and includes receiver timestamp.

Heartbeat messages do not convey authorization or routing authority.

## 8. Stream open

For a validated public route, the Gateway opens a logical stream by sending `stream_open` on a new non-zero stream ID.

The payload contains only:

- `endpoint_id` — public endpoint identifier;
- `assignment_id` — external route-assignment identifier;
- `local_endpoint_id` — opaque identifier of an Agent-local approved mapping;
- `request_id` — correlation identifier.

The payload does **not** contain an IP address, hostname, URL, scheme, file path, socket path, or arbitrary local target. The Agent resolves `local_endpoint_id` against its own locally approved mapping and independently enforces the local-target/SSRF policy.

## 9. Data

Kind `0x02` data frames contain opaque stream bytes.

Rules:

- stream ID must be non-zero and currently open;
- payload may be zero-length only when explicitly tolerated by the implementation, but zero-length data has no control meaning;
- payload size must not exceed 1 MiB;
- data carries no JSON control metadata.

## 10. Stream close and error

`stream_close` performs normal stream shutdown and contains a bounded `reason_code`.

`stream_error` terminates the stream because of a failure and contains:

- stable `code`;
- bounded human-safe `message` suitable for diagnostics;
- `retryable` boolean.

Error text must not contain secrets, session tokens, private keys, or full sensitive payloads.

## 11. Revocation

The Gateway may send `session_revoked` on stream ID `0` after it consumes a valid external revocation/disable signal.

A revoked session must stop opening new streams and terminate according to the later runtime implementation's bounded shutdown procedure. This message does not create Control Panel ownership inside the Gateway; it is the runtime consequence of an external authority signal.

## 12. Unknown / malformed input

The receiver rejects:

- unsupported protocol versions;
- unknown frame kinds;
- non-zero reserved flags;
- invalid UTF-8 control payloads;
- malformed JSON;
- unknown control `message_type` values;
- unknown JSON fields;
- fields outside schema lengths/ranges/patterns;
- replayed/out-of-order sequence values;
- invalid stream scope for a control message;
- oversized payloads;
- payload-length mismatch.

No malformed input is reinterpreted as a different message type.

## 13. External Control Panel independence

The tunnel protocol does not call a Control Panel CRUD API and does not read a Control Panel database. Gateway runtime implementations consume externally provided contract records defined under `contracts/v1/external/` through an integration adapter in a later implementation leaf.

AG-3 test fixtures stand in for that external source so the contract can be exercised without implementing the Control Panel.
