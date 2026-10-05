# ADR-0017: Private Connector ingress for TCP and RDP

Status: Accepted  
Date: 2026-09-27

## Context

The existing Agent/Gateway tunnel already carries bounded opaque TCP bytes to
an Agent-owned loopback mapping, but its only ingress is a public HTTP hostname.
Private TCP (including RDP) needs authenticated client ingress without exposing
a public listener, disclosing a raw Agent target, or turning the Gateway into
Control Panel business authority.

## Decision

Add a separate native Connector client and a dedicated Gateway WSS endpoint.
The Connector binds loopback only and opens one authenticated WSS flow per
accepted local TCP connection. It never accepts a public bind address.

The Panel issues a short-lived, random bearer token exactly once. Only its
SHA-256 digest is persisted and published in a `connector_grant` v2 record.
Each grant is scoped to one stable endpoint ID, has a bounded lifetime and an
explicit `max_connections` no greater than 16. Complete metadata generations
remain the read-only Gateway authority; the Gateway never reads the Panel DB.

The Gateway accepts a Connector flow only when all of these are true:

- the grant exists, is active, unexpired and its token digest matches in
  constant time;
- the referenced v2 endpoint exists, is enabled, and has `private` or `both`
  exposure;
- its protocol is TCP and the owning Device has a routable authenticated Agent
  session;
- grant, endpoint, Device, session and global concurrency budgets all admit
  the connection.

Connector requests contain opaque grant/endpoint identifiers only. They never
contain an Agent-local address. The Gateway opens the existing logical tunnel
stream with the endpoint's `local_endpoint_id`; the Agent independently maps
that ID to its approved loopback target.

The Connector wire stream uses bounded binary frames and an explicit
write-half-close signal. Gateway↔Agent gains the corresponding negotiated
stream half-close control. A half-close stops one write direction without
discarding queued bytes in the other direction. Cancellation, timeout,
revocation, transport loss and budget exhaustion deterministically close both
directions and release all reservations.

Agent and Gateway use one required `hooshix.tunnel.v1` WebSocket subprotocol
that includes bound resume proofs and stream half-close. A missing or different
subprotocol is rejected; no mixed-version compatibility path is retained before
the first production release.

RDP is TCP with `application_protocol: rdp`. This hint is optional for legacy
records, where omission means `generic`. An RDP endpoint is valid only with
`protocol: tcp` and `exposure: private`; `both` and `public` are rejected by
the contract, Panel and Gateway. Public RDP is outside this phase.

## Security and operational rules

- Production Connector and Agent transports require WSS with certificate
  verification; there is no insecure fallback.
- Grant tokens never appear in URLs, logs, metadata files or status labels.
- Failed authentication is indistinguishable at the public boundary and does
  not disclose whether a grant or endpoint exists.
- Listener, handshake, frame, queue, byte, connection and idle-time budgets are
  finite. Metrics use low-cardinality result/reason labels only.
- Grant disable/expiry prevents new flows. A metadata refresh that revokes a
  live grant cancels its active flows within the bounded refresh interval.

## Rejected alternatives

- Publishing RDP directly on a public TCP port: rejected by the private-by-
  default requirement and brute-force exposure.
- Reusing account passwords or web-session cookies in the Connector: rejected
  because it broadens credential scope and storage impact.
- Putting a raw target in a grant or Connector request: rejected because it
  bypasses Agent-owned target policy.
- One long-lived unscoped API token: rejected because compromise would expose
  every endpoint indefinitely.
- A second data plane beside the existing logical streams: rejected because it
  duplicates framing, limits, cancellation and observability.

## Verification

- Contract parsers reject malformed, unknown, duplicate and raw-target fields,
  invalid lifetimes/digests, excessive connection limits and public RDP.
- Panel tests cover one-time token return, hashed persistence, ownership,
  expiry/disable and endpoint scoping.
- Gateway tests cover invalid tokens, private exposure, offline/revoked Device,
  concurrency, cancellation, half-close and budget release.
- A real loopback TCP echo flow classified as RDP traverses Connector → Gateway
  → Agent and preserves both half-closes. No claim of RDP UI/login success is
  made without a Windows host acceptance run.

## Compatibility

Existing v1 public HTTP routes and v2 service endpoints remain valid. The new
`application_protocol` field is optional and omission means `generic`. The
`connector_grants` metadata category is optional until private Connector
ingress is enabled. Peers that do not negotiate half-close are not offered
private Connector traffic.
