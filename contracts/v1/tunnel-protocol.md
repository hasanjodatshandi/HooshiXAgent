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
- each subsequent frame is exactly the previously accepted sequence plus `1`; gaps are invalid;
- a receiver rejects repeated, lower, skipped, or otherwise non-contiguous sequence values;
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

Every v1 timestamp uses RFC3339 in UTC with the literal upper-case `Z` suffix. Seconds are required; an optional fractional second uses a dot (for example, `2026-08-29T12:00:00.123Z`). Numeric offsets, lower-case separators/suffixes, comma fractions, and leap-second spellings are not part of this contract. Component ranges are bounded (month `01..12`, day `01..31`, hour `00..23`, minute `00..59`, second `00..59`) and the calendar date must exist, so `2026-02-30T12:00:00Z` is invalid. The fractional second is bounded to 1..9 digits (nanosecond precision); a `timestamp` is therefore never longer than 30 characters.

Numbers in this contract are **integer literals**. A fraction or an exponent is invalid even when it denotes a whole number: `1.5`, `1e3`, and `1000.0` are all rejected for an integer field. Consumers decode integers with `strconv.ParseInt`/`strconv.ParseUint` semantics at the field's declared width, so a value outside the declared `minimum`/`maximum` (for example a `next_sequence` above `18446744073709551615`) is invalid. JSON Schema cannot express this literal-form rule portably, so it is normative here rather than in the schema.

Base64url fields are **canonical**: the field is the unpadded base64url encoding of exactly the declared number of bytes, and re-encoding the decoded bytes must reproduce the transmitted string exactly. A value that decodes to the right length but is not the canonical encoding — for example a 43-character nonce whose discarded trailing bits are non-zero — is invalid. JSON Schema can only bound the length and alphabet, so consumers must enforce canonicality themselves.

Invalid UTF-8 is rejected before JSON semantic processing. Duplicate JSON object member names are invalid and must be rejected, even when the duplicate values are identical. Unknown fields are rejected. An explicit JSON `null` is invalid for **every** member: no v1 control member is nullable, so a `null` is exactly as malformed as an absent member. Strings are length-bounded by the schema, counting Unicode code points rather than UTF-8 bytes. Identifiers are opaque and must match the schema identifier pattern; implementations must not infer account, tenant, billing, or database semantics from them.

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

## 11a. Health report

`health_report` is an Agent→Gateway session-level control message on stream ID `0` carrying bounded operational counters only:

- `report_id` — opaque correlation identifier;
- `generated_at` — RFC3339 UTC generation time;
- `active_streams` — current registered streams (bounded by contract);
- `queued_frames` — queued inbound frames across live streams (bounded by contract);
- `reconnect_count` — completed reconnect cycles since Agent process start, in the inclusive range `0..2147483647`;
- `last_reconnect_at` — optional RFC3339 UTC timestamp of the last reconnect;
- `agent_version` — optional bounded version string.

Health reports are telemetry only. They refresh liveness observation on the Gateway but never carry or imply authorization, routing, revocation, or target authority. The Gateway counts them in aggregate low-cardinality metrics and never exposes identifiers as metric labels.

## 11b. Session resume

Per ADR-0015, this extension is enabled **only** when the verified WSS
handshake selects the `hooshix.resume-proof.v1` WebSocket subprotocol. New
Agents offer it and new Gateways select it when offered. Without that selection,
the Gateway emits the original `session_ready` shape (no `resume_challenge`)
and the Agent uses full authentication, even if it retained old resume material.
With the extension selected, `resume_challenge` is mandatory and validated;
absence is an error, not a downgrade. Resume on an unnegotiated connection is
rejected. Both full and resume handshakes have a finite handshake deadline.

The JSON schema allows the baseline and extended `session_ready` shapes;
the runtime must additionally enforce the negotiated shape through
`ValidateReadyNegotiation`. Frame version and external metadata version stay 1.

`resume_session` is an Agent→Gateway session-level fast-path request on stream ID `0` sent as the first control frame of a new WebSocket connection after a transport interruption:

- `device_id`, `authorization_id`, `token_id` — the same externally issued identity triple used by `client_hello`;
- `session_id` — the previously authenticated session being resumed;
- `resume_nonce` — 32 fresh random bytes base64url without padding;
- `resume_challenge` — the Gateway-issued per-transport challenge this device received in the `session_ready` (or the latest `session_resumed`) of the transport being replaced, echoed verbatim;
- `issued_at` — RFC3339 UTC instant at which the Agent produced this proof;
- `signature` — 64-byte Ed25519 signature over the exact transcript:

```text
HXT1-RESUME\x00
|| device_id || \x00
|| authorization_id || \x00
|| token_id || \x00
|| session_id || \x00
|| resume_nonce || \x00
|| resume_challenge || \x00
|| issued_at
```

The Gateway accepts the resume only when **all** of the following hold:

1. the referenced session is currently live and authorized for that exact device;
2. the current external authorization record matches the resume subject, is active, unexpired, and not revoked;
3. the signature verifies against the externally registered device public key;
4. `resume_challenge` equals the challenge the Gateway issued for that session identity over the transport being replaced (constant-time comparison), and that challenge has not already been consumed by an accepted resume;
5. `issued_at` is within the Gateway's acceptance window of the Gateway clock.

The Gateway issues `resume_challenge` in `session_ready` (one per transport) and rotates it in every `session_resumed`, so an accepted proof is consumed: a captured `resume_session` frame can never be replayed against the same session identity, and the acceptance window bounds how long any captured proof remains usable at all. Because requirement 5 compares an Agent-supplied timestamp against the Gateway clock, an Agent whose clock is outside the window simply loses the fast path and falls back to the full handshake; it is never granted anything.

On success the Gateway replies `session_resumed` with the same `session_id`, a `next_sequence` value in the inclusive unsigned 64-bit range `1..18446744073709551615`, a `resumed_at` timestamp, and a freshly rotated `resume_challenge` for the following transport. Sequence numbering restarts independently on each new transport per Section 3: the resume reply itself is sequence `1` in the Gateway→Agent direction and the resume request is sequence `1` in the Agent→Gateway direction; `next_sequence` advertises the exact following value so the Agent can arm its inbound tracker deterministically.

Any rejection fails closed:

- unknown/expired/replaced session, authorization change, signature failure, revocation, challenge mismatch, or a proof outside the acceptance window all reject the resume;
- a rejected resume closes the connection with WebSocket close code `1013` (`TryAgainLater`), defined in Section 11c, so the Agent falls back to a full `client_hello` handshake on its next bounded reconnect attempt. This includes an Agent that sends the pre-challenge transcript shape: it fails `resume_session` validation and is treated as an unavailable resume rather than an authentication failure, so the designed full-handshake fallback still applies;
- a resume may never bypass authentication, authorization freshness, or revocation enforcement.

Session resume does not transfer stream state: streams were bound to the lost transport and are re-established by ordinary traffic. Existing sessions terminate through the same lifecycle as a reconnect replacement.

## 11c. WebSocket close codes

A close code is the only out-of-band signal a peer can send after the frame layer has already accepted traffic, so v1 fixes which codes are permitted and what each obliges the Agent to do. A code used with a trigger outside its row is a contract violation.

| Code | Name | Meaning | Permitted trigger | Required Agent action |
| ---: | --- | --- | --- | --- |
| 1000 | `NormalClosure` | The session ended cleanly. | Either peer ending an authenticated session on purpose: Agent shutdown, or the Gateway replacing an older session with the device's newer reconnect. | Treat as an ordinary end of session. No authorization is implied for the replacement; reconnect only through the normal bounded policy. |
| 1001 | `GoingAway` | The endpoint is going away. | Gateway shutdown or drain. | Reconnect with bounded backoff. |
| 1002 | `ProtocolError` | A frame or sequence violation was observed. | Reserved flags set, unknown frame kind, unsupported version, non-contiguous sequence. | Permanent. Stop the session and do not retry without operator action. |
| 1003 | `UnsupportedData` | The peer cannot accept that data type. | A frame type the peer does not implement. | Permanent. Stop the session. |
| 1007 | `InvalidFramePayloadData` | The payload was not acceptable data. | Control payload that is not valid UTF-8, or otherwise malformed at the payload layer. | Permanent. Stop the session. |
| 1008 | `PolicyViolation` | Authenticated peer violated a policy rule. | Authentication or authorization failure, message outside its stream scope, unknown/malformed control message, `session_revoked` handling, idle timeout, or sequence exhaustion. | Permanent for every reason except the benign peer-initiated ends (`idle timeout`, `session ended`), which are ordinary ends. Never treated as a reason to retry with weaker checks. |
| 1009 | `MessageTooBig` | A frame exceeded the peer's limit. | Any frame above the Section 2 contract maximum. | Permanent. Stop the session. |
| 1011 | `InternalError` | The peer hit an internal failure. | Gateway-side failure such as unavailable heartbeat entropy or a failed control write. | Transient. Reconnect with bounded backoff. |
| 1012 | `ServiceRestart` | The service is restarting. | Gateway restart. | Transient. Reconnect with bounded backoff. |
| 1013 | `TryAgainLater` | The connection was refused for a capacity or availability reason. | Gateway handshake rate limit, per-device admission limit, session capacity reached, temporarily stale/unavailable metadata, or **a rejected `resume_session`**. | Transient, and configuration-preserving. On a rejected resume the Agent **must** fall back to a full `client_hello` handshake (Section 6) on its next bounded reconnect attempt; it must not retry the resume, must not treat the close as authorization, and must not skip authentication or authorization freshness. |
| 1014 | `BadGateway` | An intermediary failed. | Gateway or edge proxy failure. | Transient. Reconnect with bounded backoff. |

A close code carries no authority. In particular `1013` only tells the Agent to try again later; every new connection must authenticate again from scratch, and a rejected resume is never evidence that the previous session is still valid.

## 12. Unknown / malformed input

The receiver rejects:

- unsupported protocol versions;
- unknown frame kinds;
- non-zero reserved flags;
- invalid UTF-8 control payloads;
- malformed JSON;
- duplicate JSON object member names at any nesting depth;
- unknown control `message_type` values;
- unknown JSON fields;
- fields outside schema lengths/ranges/patterns;
- repeated, lower, skipped/gapped, wrapped, or otherwise non-contiguous sequence values;
- invalid stream scope for a control message;
- oversized payloads;
- payload-length mismatch.

No malformed input is reinterpreted as a different message type.

## 13. External Control Panel independence

The tunnel protocol does not call a Control Panel CRUD API and does not read a Control Panel database. The current Gateway consumes externally provided contract records defined under `contracts/v1/external/` through its read-only integration adapter; any alternate external adapter must preserve this contract boundary and must not introduce direct Control Panel database authority.

AG-3 test fixtures stand in for that external source so the contract can be exercised without implementing the Control Panel.
