# Phase 3 HTTP endpoint acceptance

Status: complete on 2026-09-27.

## Delivered behavior

- A new or re-enabled endpoint can target only an enabled Device with a
  currently valid, non-revoked session authorization.
- Move/repair preserves the public hostname and stable endpoint ID while
  replacing the route-assignment ID, changing the owner/local endpoint and
  incrementing the v2 endpoint revision in one SQLite transaction.
- The retired assignment receives an append-only `assignment_revoked` event.
  It is never reused by enable or move.
- The dashboard offers only currently routable Devices as create/move targets
  and marks an existing endpoint whose Device no longer has a valid session.
- Publisher generation construction reads authorizations, v1 hostname routes,
  revocations and v2 service endpoints from one database snapshot. The
  immutable generation is fully written before `current.json` is replaced.

## Verification evidence

The Panel suite ran with
`HOOSHIX_CONTRACTS_DIR=D:\Projects\hooshixagent-rebuild\contracts\v1`:

- 29 tests passed, 0 failed, 0 skipped;
- the moved endpoint has the same hostname/endpoint ID in v1 and v2;
- v1 and v2 agree on target Device and local endpoint;
- the old assignment remains present in revocations;
- an ineligible move is rejected with no row or revocation mutation;
- expired/revoked credentials cannot receive or re-enable routes;
- all emitted records validate against the Agent/Gateway contract schemas.

`npm run typecheck` and `go test ./...` also passed. The Go run includes Gateway
live/static metadata and service-endpoint compatibility coverage.

## Scope boundary

This phase preserves the existing Caddy HTTPS hostname ingress and v1 Gateway
route behavior while adding the v2 control-plane model. It does not claim a
production-network tunnel acceptance run; that remains coupled to the pending
real HTTPS/WSS and second-PC gate documented for Phase 2. TCP/RDP begins in
Phase 4.
