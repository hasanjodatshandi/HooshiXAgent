# Phase 6 UDP/QUIC acceptance

Status: in progress; private and public UDP paths implemented and tested locally.
Do not deploy or enable public UDP ingress until the real-network gates pass.

## Completed Agent slice

- ADR-0019 fixes UDP mode: one tunnel data frame per datagram, at most 1200
  bytes. QUIC is opaque UDP, not a separately parsed or terminated protocol.
- Agent endpoint mappings opt into `udp`; legacy mappings remain TCP. CLI and
  local UI can create a UDP loopback mapping. A mode/mapping mismatch and any
  non-loopback target fail closed.
- A connected socket isolates each flow; byte and frame queues use existing
  limits. Oversize datagrams terminate only their flow. Idle/cancel closes it.
- UDP loopback echo, datagram boundary, protocol mismatch, contract agreement,
  full Go suite, vet, and targeted race checks passed locally.

## Completed private slice

- Panel accepts private UDP endpoints and issues the existing short-lived,
  owner-scoped Connector grant.
- A loopback UDP Connector maps each peer to a distinct bounded flow; the
  Gateway checks the grant and explicit UDP intent before opening an Agent
  flow. The Gateway preserves one frame per datagram through queued and
  terminal reads.
- A real Agent + Gateway + Connector + loopback UDP echo integration test
  returned two differently sized datagrams intact. A second peer over the
  Connector flow cap and an oversize datagram were dropped while the admitted
  flow continued. A real HTTP/3 handshake and request also passed through a
  private Connector flow with a 1200-byte QUIC packet profile; repeated race
  runs passed.

## Completed public slice (local only)

- Panel reserves public UDP ports with the same durable unique lease and
  canonical IPv4 source-CIDR policy as public TCP. The v2 contract and Gateway
  metadata projection distinguish TCP and UDP; one numeric port is reserved
  to only one endpoint even across protocols.
- Gateway A's opt-in `-public-udp-bind` reconciles UDP listeners from live
  metadata. A source-approved IP:port gets one bounded datagram flow to the
  Agent; oversize datagrams drop, and listener removal cancels active flows.
- A real Agent + Gateway + public UDP listener + loopback echo integration test
  passed. A real HTTP/3 handshake and request passed through a public UDP
  listener. A 32-packet denied-source probe produced no response while the
  listener was bound; the allowed flow survived oversize drops. Panel
  contract-backed publication tests passed with the sibling schemas; repeated
  targeted race tests and a listener-disable test passed.
- The existing production firewall allows public TCP, not UDP. No Phase 6
  binary or firewall change has been deployed.

## Remaining gates

1. Public UDP live-metadata revocation/cancellation checks and a
   reflection/amplification assessment for the intended UDP service and source
   CIDRs.
2. Controlled firewall deployment, two-network Internet allow/deny checks, disable,
   revocation, restart, backup, and rollback evidence.

No production Phase 6 component has been deployed.
