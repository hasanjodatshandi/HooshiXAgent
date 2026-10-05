# ADR-0018: Public TCP ingress with explicit port leases

Status: Accepted
Date: 2026-09-28

## Context

Generic TCP cannot share Caddy's hostname-routed HTTP listener. The control
plane therefore needs a durable, collision-safe address that the Gateway can
reconcile without reading the Panel database or receiving raw Agent targets.

## Decision

- A public generic-TCP `ServiceEndpoint` owns one explicit `public_port` and
  one to sixteen canonical IPv4 `allowed_source_cidrs` entries.
- The Panel allocates the lease transactionally. A partial unique database
  index makes one enabled or disabled endpoint the sole owner until deletion.
- Only Gateway replica A owns the public TCP socket range. Replica B remains
  available for Agent tunnel failover and never competes for the same ports.
- Gateway reconciles the immutable metadata projection every second. Missing,
  stale, malformed or changed authority closes the affected listener and its
  active flows. An OS port collision stays closed and is retried.
- Source policy and bounded rate/concurrency admission run before a tunnel
  stream is opened. Gateway sends only the opaque local endpoint ID to Agent.
- TCP payloads are transparent and support half-close. Caddy is not in this
  path and no TLS semantics are inferred for arbitrary application protocols.
- RDP remains private-only. Public TCP endpoints are classified `generic`.

IPv6 source policy is deliberately deferred. The first production slice binds
IPv4 and rejects IPv6 CIDRs at the Panel and contract boundaries.

## Consequences

Disabling an endpoint closes ingress but retains its leased port; deleting it
releases the lease. The configured host firewall/security group must permit the
same bounded port range. Public TCP availability currently follows replica A;
active-passive listener ownership is a later HA concern, not a shared bind.

## Verification / fitness functions

- Contract tests reject missing ports, non-canonical CIDRs and public RDP.
- Panel tests cover range validation, unique leasing and published policy.
- A real-Agent integration test sends raw TCP through the public listener to a
  loopback service and verifies bidirectional half-close.
- Race tests cover Gateway and integration packages.

## Rollback/supersession

Remove the replica-A public-TCP flags and restart it; metadata and Panel rows
remain intact, but no public TCP sockets are owned. A later HA/IPv6 design must
supersede this ADR explicitly.

Related ADRs: ADR-0003, ADR-0005, ADR-0006, ADR-0012, ADR-0015, ADR-0017.
