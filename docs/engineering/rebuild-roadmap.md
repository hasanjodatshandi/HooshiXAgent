# HooshiX rebuild roadmap

This branch rebuilds the requested product from the green v1 baseline. The
original dirty working tree is preserved in `D:\Projects\hooshixagent` and is
reference material only.

## Delivery rule

Every phase is a reviewable vertical slice. It must format, compile and pass its
unit, contract, integration, failure-path and architecture checks before the next
phase begins. Security and data-integrity failures block delivery.

## Phases

1. **Baseline and contract foundation — complete (2026-09-27)**
   - clean Agent/Gateway and Panel worktrees;
   - versioned `ServiceEndpoint` contract;
   - atomic Panel publication and Gateway live loading;
   - ordered Panel database migrations;
   - no TCP/UDP runtime behavior yet.
2. **Enrollment and multi-device lifecycle — implementation complete; two-PC runtime gate pending**
   - short-lived one-time enrollment request;
   - browser approval plus Agent key-possession proof;
   - Setup uses the configured server and never collects the account password;
   - revoke/re-pair/reinstall and two-device tests.

   Implementation status: migration v3, the one-time state machine, Ed25519 proof,
   authenticated browser approval, single-use claim API, bounded request bodies,
   rate limiting and two-device/replay/expiry tests are implemented. Setup now
   asks for the Panel origin and Device name, delegates the exchange to the
   authenticated loopback service, opens the approval page and waits for the
   service to commit the credential inside its LocalSystem DPAPI boundary.
   Re-enrolling the same key under the same owner repairs the existing Device
   and rotates its authorization instead of creating a duplicate. The remaining
   gate is an elevated real-Setup/two-PC acceptance run; see
   `phase-2-enrollment-acceptance.md`.
3. **HTTP/HTTPS parity on the v2 model — complete (2026-09-27)**
   - existing hostname routes remain compatible;
   - endpoint move/disable/revoke are atomic and fail closed.

   Panel endpoint assignment now requires a currently valid Device session.
   Move/repair keeps the stable endpoint ID and hostname, permanently revokes
   the previous route-assignment ID, issues a fresh assignment, and increments
   the v2 revision in one SQLite transaction. Publication builds v1 routes,
   v2 service endpoints, authorizations and revocations from one database
   snapshot before atomically activating the generation. Contract-backed tests
   cover move, disable, re-enable, revoked/expired credentials and rejection
   without partial state. See `phase-3-http-endpoint-acceptance.md`.
4. **Private TCP and RDP — complete (2026-09-28)**
   - bounded TCP streams, half-close and cancellation;
   - scoped Connector grants; RDP private-only by default.

   The control and data planes are implemented: ADR-0017, strict grant and
   endpoint contracts, one-time hashed grant issuance, the loopback Connector
   binary, dedicated authenticated WSS ingress, negotiated half-close, bounded
   admission and cancellation, and live grant revalidation. An automated real
   Connector → Gateway → Agent → loopback TCP test covers the complete path
   with an RDP-classified endpoint. A two-machine Windows run also completed
   an interactive RDP login and proved that revoking the exact grant makes the
   next attempt fail closed with HTTP 401; see
   `phase-4-private-tcp-rdp-acceptance.md`.
5. **Public TCP — complete (2026-09-29)**
   - explicit port leases, listener reconciliation, collision/source policies.

   Panel migration 5, durable unique leases, IPv4 source policy, Gateway
   listener reconciliation, bounded raw-TCP forwarding and a real-Agent
   integration path are implemented. Production activation, real Internet
   echo, source rejection, disable/re-enable, and Gateway restart passed.
   The user accepted the phase without a separate UI-disable latency timing
   measurement; see
   `phase-5-public-tcp-acceptance.md` and ADR-0018.
6. **Native UDP/QUIC — in progress (private and public paths tested locally)**
   - Agent first, then private Connector, then public UDP;
   - bounded flows/queues/datagrams and real-network acceptance tests.

   ADR-0019 fixes one-frame-per-datagram semantics and a 1200-byte initial
   profile. Agent, Gateway, Connector, and Panel pass a real private UDP echo
   integration test. Public UDP port leases, source policy, an opt-in Gateway
   listener, and a real-Agent echo integration test are implemented locally.
   Real HTTP/3 handshakes through private and public UDP paths now pass in
   local integration. Real-network acceptance remains pending; see
   `phase-6-udp-quic-acceptance.md`.
7. **Modern Panel UI and production rollout**
   - TypeScript API and React/Tailwind dashboard;
   - migration, backup/restore, canary and rollback evidence.

## Cross-component invariants

- Caddy owns public web TLS; Gateway owns generic TCP/UDP data-plane listeners.
- Panel owns durable users/devices/routes/grants; Gateway never reads its DB.
- Agent private keys never leave the device.
- Gateway/Connector input selects only an opaque local endpoint ID, never a raw
  Agent-side address.
- HTTP uses hostname/path routing. Generic TCP/UDP/RDP uses an explicit port.
- Public exposure is opt-in; RDP is not public by default.
