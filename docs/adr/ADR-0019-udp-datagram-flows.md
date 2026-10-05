# ADR-0019: UDP datagram flows for private Connector and public ingress

Status: Accepted
Date: 2026-09-29

## Decision

- QUIC is carried as opaque UDP datagrams; HooshiX does not parse or terminate
  QUIC. Each tunnel data frame is one complete datagram and may not be split.
- A flow uses a stable connected UDP socket to an Agent-approved loopback
  target. The Agent configuration marks the mapping `udp`; a mismatched
  `stream_open.mode` fails closed. No Gateway message carries a raw target.
- The initial profile caps datagrams at 1200 bytes, each flow at the existing
  bounded stream/queue budgets, and idle lifetime at the configured timeout.
  Oversize datagrams terminate that flow without corrupting another flow.
- Private UDP uses a scoped Connector grant and a loopback UDP listener. Public
  UDP uses a leased port and source CIDR policy. Gateway A is the only public
  listener owner, as for TCP. Caddy remains outside both UDP paths.
- Revocation, endpoint disable, stale metadata, device disconnect, and grant
  expiry cancel active flows and prevent new ones. No implicit public access.

## Sequence

Implement the Agent datagram target and tunnel profile first, then private
Gateway/Connector flow handling, then Panel public leases and Gateway UDP
listeners. Ship each slice with bounded-flow and real-network checks. Do not
enable public UDP until all three parts pass together.

## Consequences

Datagrams above 1200 bytes are not transported, including QUIC packets that
exceed this profile; a future larger-datagram design needs an explicit MTU and
fragmentation decision. Encapsulating UDP in the existing WebSocket transport
also inherits its head-of-line behavior, so this is functional UDP/QUIC
connectivity rather than a native QUIC transport for the HooshiX control plane.
Public UDP services can reflect traffic to spoofed source addresses; a bounded
CIDR policy alone is not proof of address ownership. Production activation
requires a separate reflection/amplification review of the selected service
and allowed sources.
