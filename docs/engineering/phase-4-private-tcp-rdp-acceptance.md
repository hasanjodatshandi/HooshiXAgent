# Phase 4 private TCP and RDP acceptance

Status: accepted on 2026-09-28 with a real two-machine Windows RDP login and
post-revocation fail-closed verification.

## Delivered behavior

- The Panel can create private generic-TCP or RDP endpoints for an owned,
  currently authorized Device and issue a short-lived endpoint-scoped grant.
- The raw Connector token is returned once. Only its SHA-256 digest is stored
  and published; disable, expiry and endpoint changes fail closed.
- `hooshix-connector` reads the token from a bounded regular file, listens only
  on an explicit loopback IP and opens one authenticated WSS flow per local TCP
  connection.
- Gateway admission binds the token, token ID, grant, endpoint and online
  Device before accepting the WebSocket. Per-grant, per-Device and global
  concurrency remain bounded.
- Gateway and Agent require the single `hooshix.tunnel.v1` subprotocol, which
  includes bound resume proofs and TCP half-close. No legacy fallback remains.
- Active flows are reauthorized every second. Grant revoke/expiry or endpoint
  remapping cancels the stream and releases its reservations.
- The Panel process is the only metadata lease publisher. The superseded
  standalone watchdog is disabled to avoid competing revision writers.
- RDP is a private-only TCP application classification. No public RDP listener
  is created in this phase.

## Automated evidence

`go test ./...` includes a real in-process network path:

1. Connector accepts a loopback TCP client and authenticates to Gateway over
   TLS WebSocket.
2. Gateway authorizes an RDP-classified private endpoint and opens a logical
   TCP stream on an authenticated real Agent session.
3. Agent resolves only its configured opaque local endpoint ID and connects to
   a loopback TCP echo service.
4. Client and service both half-close their write side; `echo:hello` returns
   before the stream closes.

Separate tests cover malformed contracts, wrong tokens/IDs, private exposure,
grant expiry/revocation, bounded connection counts, insecure/public Connector
configuration, metadata loading and cancellation of an already-active grant.
The Panel contract, type and test suites validate issuance, hashed persistence,
ownership, endpoint scoping, disable and projection.

Final local verification on 2026-09-27 passed:

- `go vet ./...` and `go test ./... -count=1`;
- race detection for Agent, Connector, Gateway and integration packages;
- Panel `npm test`: 32 passed, 0 failed, 0 skipped;
- Panel `npm run typecheck` and `npm run build`;
- `git diff --check` in both rebuild repositories.

## Observed two-machine Windows acceptance

The manual gate ran on 2026-09-28 with the Agent on `QUANTUM` and the
Connector/RDP client on `Quantum2`:

- the Agent was connected as `device-K4pMBl9rWtyU` and mapped the opaque local
  endpoint `rdp-local` to `127.0.0.1:3389`;
- the Connector listened on `127.0.0.1:13389`, read its scoped token from a
  file (not process arguments), and used a grant bounded to four concurrent
  connections;
- three independent protocol probes returned a valid Windows RDP negotiation
  response through Connector -> Gateway -> Agent before the UI test;
- `mstsc` on Quantum2 completed an interactive login to QUANTUM through that
  loopback Connector address; the operator explicitly confirmed success;
- the Panel then disabled the exact live grant and published a generation in
  which it was absent; the next RDP attempt failed closed and the Connector
  reported `HTTP 401`, confirmed by the operator;
- published metadata contained only the token SHA-256 digest. The raw token
  was absent from process arguments, Gateway metadata and logs, and the
  temporary token file was removed after the test.

Windows presented QUANTUM's ordinary locally generated RDP certificate and
its expected trust warning; it was accepted for this private acceptance run.
Installing an enterprise-trusted RDP certificate is a deployment policy task,
not part of the tunnel protocol. Seamless continuation of an already-open RDP
session across a forced network interruption was not claimed; a lost flow is
re-established as a new Connector connection under a still-valid grant.
