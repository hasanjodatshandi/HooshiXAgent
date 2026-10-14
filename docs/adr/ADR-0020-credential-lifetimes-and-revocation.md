# ADR-0020: Connector grant and device credential lifetimes

Status: Accepted  
Date: 2026-10-14

Supersedes in part: ADR-0017 (the grant-lifetime and connection-budget clauses
of its Decision section). ADR-0017 remains current authority for everything
else, including the Connector's loopback-only binding, the private-by-contract
RDP rule, the WSS requirement and the constant-time digest comparison.

## Context

The Panel issued every connector grant with a lifetime an operator picked from
1 to 60 minutes, defaulting to 15, and with an operator-chosen
`max_connections`. In real use an RDP session outlives an hour. When a grant's
`expires_at` passed, the Gateway's once-per-second re-authorization cancelled
the live flow, and every later handshake answered `HTTP 401`. The Connect window
reported that only as a failed client flow while its listener went on saying
`tunnel ready`, and the saved `hooshix-connect.cfg` kept replaying the dead
credential, so the operator's experience was a session that died on a clock and
then could not be restarted from the machine that had been using it.

`expires_at` cannot simply disappear. It is a mandatory member of both authority
records: contractv1 device-session authorizations and contractv2 connector
grants require the field and require `not_before < expires_at`, the Panel's
publisher validates that ordering before it writes a generation, and the
Gateway rejects a generation that omits or misorders it.

## Decision

1. `expires_at` stays mandatory and keeps its meaning on the wire. "Unlimited"
   is an issued value one hundred years out, defined once in the Panel's
   `src/domain/lifetime.ts`. The Gateway, the contract validators, the published
   metadata shape and the Agent are unchanged by this decision.
2. The Panel's issue form keeps `ttl_minutes`, with no pre-filled value and no
   upper bound. Empty means unbounded; a whole number of at least 1 means that
   many minutes. The 60-minute ceiling is removed.
3. `max_connections` is no longer operator input. Every grant carries the
   contract maximum, 16. An RDP client opens a companion TCP connection while it
   negotiates and the Connector takes one grant slot per local connection, so a
   narrow budget answered the second connection with
   `503 connector capacity reached`.
4. Device session authorizations are issued under the same rule, so a paired
   Agent stays paired until it is disabled, re-paired or revoked. Re-pairing a
   device still revokes its previous authorization, as before.
5. Revocation becomes the retirement control. Revoke marks the record disabled,
   the publisher stops publishing it as authority, and the Gateway's
   per-second re-authorization ends a live flow within one tick. The Connect
   window's hint says so instead of describing a lifetime that no longer
   applies.
6. The enrollment-code window is **not** changed. ADR-0016's ten-minute code
   bounds a pairing approval, not a session, and removing it would let an
   observed code mint a device forever.

## Security and operational rules

- A leaked or copied connect bundle is now usable until an operator revokes it.
  That is the accepted cost of this decision; the compensating controls are the
  Panel's grant list, Revoke's one-tick effect on live flows, and the fact that
  the bundle only reaches an endpoint its grant is scoped to.
- Un-expired grants accumulate against the per-endpoint cap of 16 active grants.
  That count now means un-revoked, not in-use, so retiring old bundles is an
  operator action rather than something time does by itself.
- A status line may not claim a tunnel is usable when its credential has been
  revoked. The listener state and the flow state stay separate, and a refused
  flow names the Gateway's answer.
- Grant tokens still never appear in URLs, logs, metadata files or status
  labels, and only their SHA-256 digest is stored or published.

## Rejected alternatives

- Dropping `expires_at` from the contract: rejected. It breaks both contract
  versions, the publisher's ordering check and every stored fixture, and would
  force a Gateway redeploy to express a policy the issuing side already owns.
- Raising the ceiling from 60 to some larger fixed number: rejected. It is still
  a clock that kills a working session, which is the failure being removed.
- Having the Connector re-request a bundle from the Panel when one is refused:
  rejected. It needs a Panel credential on the connecting machine, which
  broadens credential scope exactly as ADR-0017's rejected alternatives say it
  must not.
- Removing `ttl_minutes` from the interface entirely: rejected by the operator,
  who needs the ability to hand out a deliberately short-lived bundle for a
  one-time visit.

## Verification

- Panel tests pin that a default grant is unbounded, that an explicit
  `ttl_minutes` is honoured with no upper cap, that `0`, negative and
  non-integer values are refused with `400`, and that every issued grant
  carries the contract maximum connection budget.
- The published generation is checked against the unchanged contract: the
  unbounded value is still a canonical UTC timestamp and still satisfies
  `not_before < expires_at`.
- The Gateway's expiry and revocation paths are untouched and stay covered by
  `internal/gateway/connector_authorization_test.go` and
  `authorization_lifecycle_test.go`.

## Compatibility

Grants and authorizations issued before this decision keep their stored
`expires_at` and still end on that date; the Panel shows them with their real
timestamp and shows `never` for unbounded ones. Nothing about the wire format,
the metadata generation layout or the Agent's stored secret changes, so the
decision itself breaks no device and does not touch the deployed Gateway binary.

A device paired before this decision still has to be re-paired eventually,
because its own authorization ends on the date it was issued with. There is no
renewal path: the Agent's session token arrives only at the browser-approved
enrollment claim, a refused authorization puts the supervisor in `terminal`
with the re-pair hint, and no Panel route re-issues a credential without a
fresh enrollment code. Re-pairing preserves the device key and so the same
`device_id`, which keeps existing endpoint assignments valid; it revokes the
previous authorization as it always did.
