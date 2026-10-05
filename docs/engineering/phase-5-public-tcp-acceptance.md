# Phase 5 public TCP acceptance

Status: accepted complete (2026-09-29). Live Internet transport, disable,
re-enable, and restart passed. The user explicitly waived the separate
UI-to-listener latency measurement after also exercising Disable in the Panel.

## Delivered behavior

- The Panel creates public generic-TCP endpoints with an explicit port in the
  configured `20000..29999` range and a required IPv4 source allowlist.
- SQLite migration 5 adds the durable port lease and source policy. A partial
  unique index prevents two endpoints from owning one port.
- Published v2 metadata carries `public_port` and `allowed_source_cidrs`; the
  Gateway rejects invalid records and duplicate leases atomically.
- Gateway replica A reconciles listeners from fresh metadata. Disable, delete,
  remap, revocation or stale metadata cancels the listener and active flows.
- Source CIDR, per-source rate, endpoint/device admission and global ingress
  capacity are checked before opening the Agent stream.
- Payload forwarding is raw TCP with bounded idle/write deadlines and correct
  bidirectional half-close. Caddy remains responsible only for HTTP/HTTPS.
- RDP remains private-only and cannot be published through this path.

## Automated evidence

- `go test ./... -count=1`
- `go test -race ./internal/gateway ./tests/integration -count=1`
- Real-Agent integration path: public TCP client -> Gateway listener -> Agent
  -> loopback echo service, returning `echo:public` after both sides half-close.
- Panel `npm test`, `npm run typecheck`, and `npm run build`.

## Production acceptance gate

1. Back up the Gateway binary, Panel build/dependencies/database, Panel env and
   any existing replica-A systemd override.
2. Deploy migration 5 and the new Gateway. Enable `-public-tcp-bind 0.0.0.0`
   only on replica A with the same port bounds configured in Panel.
3. Create a non-RDP local TCP endpoint on an enrolled Agent and reserve one
   unused public port with the test client's public `/32` allowlist.
4. Prove an allowed Internet client reaches the local service, then prove a
   non-allowed source is rejected before an Agent stream opens.
5. Disable the endpoint and prove the socket closes within two reconciliation
   intervals; re-enable and prove the same leased port returns.
6. Restart replica A and prove listener restoration from metadata. Confirm
   replica B does not bind the public range.
7. Record rollback path and observed results here before marking Phase 5
   complete.

## Production activation evidence (2026-09-28)

- Panel, Gateway A, and Gateway B restarted successfully and are active.
- Both Gateway readiness probes returned `{"status":"ready"}`.
- Panel `schema_migrations` contains versions 1 through 5 and the endpoints
  table has both public-TCP columns.
- Only Gateway A has `-public-tcp-bind 0.0.0.0` and range `20000..29999`;
  Gateway B has no public-TCP bind flag.
- Rollback snapshot: `/var/backups/hooshix/phase5-20260928T200030Z`.
- A temporary loopback echo service and Agent mapping `phase5-echo` ->
  `127.0.0.1:18888` returned `echo:public` locally. Port `20080` was reserved
  for this mapping. The Internet client also received `echo:public` through
  the public port, Gateway, and Agent.
- The host `nftables` input chain initially dropped external traffic to the
  public-TCP range. A rule limited to `eth0`, primary public IPv4
  `188.240.196.151`, and TCP ports `20000..29999` was installed and persisted
  in `/etc/nftables.conf`; its rollback copy is
  `/var/backups/hooshix/phase5-firewall-20260928T203540Z.conf`.
- Port `20080` is listening. An Internet connection now completes TCP setup
  and the non-allowed server-loopback source receives immediate EOF. A direct
  TCP source probe measured the Internet client's source as
  `178.252.135.162`, matching the endpoint's `/32` allowlist. HTTPS-based
  IP probes used rotating egress proxies and must not be used to infer this
  TCP client's source.
- Disabling the test endpoint through `PanelServices` removed the listener and
  a new external connection was actively refused. Re-enabling it restored the
  same port and the client received `echo:public2`. Restarting only Gateway A
  restored the listener from metadata and yielded `echo:restart`; Panel and
  Gateway B remained active.
- This service-layer test did not call the HTTP route's immediate
  `publisher.publish()`: the panel's 15-second lease loop published the
  mutation instead. Therefore it proves steady-state convergence, but does
  not measure the two-reconciliation-interval latency promised for a normal
  UI Disable action. The user confirmed a Panel Disable action and accepted
  Phase 5 without a separate timing measurement.
- Cleanup: deleted the test endpoint, verified port `20080` closed, removed
  the `phase5-echo` Agent mapping, and stopped its loopback echo process.

## Known boundary

This slice supports IPv4 source CIDRs and one active public-listener owner.
IPv6 and automatic listener failover require a later accepted design.
