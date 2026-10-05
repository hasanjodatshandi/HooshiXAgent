# ADR-0015: Unified Agent/Gateway tunnel subprotocol

Status: Accepted  
Date: 2026-09-17  
Revised: 2026-09-27

## Context

HooshiX is still in design and has no production protocol compatibility
obligation. Supporting baseline, resume-only and private-TCP variants would
create downgrade paths and duplicate tests without protecting deployed users.

## Decision

Agent and Gateway support exactly one TLS-protected WebSocket subprotocol:
`hooshix.tunnel.v1`. It includes the Ed25519 full handshake, mandatory bound
resume challenge, replay-resistant session resume, HTTP streams, TCP streams
and stream half-close. Both peers reject a missing or different subprotocol.

There is no mixed-version fallback. A protocol-breaking change before initial
production release replaces the old path. After production release, any needed
migration must be designed explicitly in a new ADR.

## Consequences

- one handshake and one security model;
- no downgrade to an unbound or capability-reduced session;
- Agent and Gateway must be deployed from the same supported release line;
- external metadata and local Agent state versions remain independent.

## Verification

Tests require the unified subprotocol, mandatory resume challenge, replay
protection and real HTTP/TCP stream behavior. Removed protocol fields and old
subprotocol names are rejected as unknown input.
