# Phase 2 enrollment acceptance

Status: automated gates and one-PC elevated packaged-Setup enrollment/repair run passed; two-PC/Gateway run pending  
Date: 2026-09-27

## Observed packaged-Setup run — 2026-09-27

Artifact: `HooshiXAgent-Setup.exe` version `0.2.0-phase2-test`, SHA-256
`8909FE5CD0BB96F5F520E407DFAD1D91C0100E4ED72A0EB3CBC3D3AE5329A7D3`.

The real UAC-elevated Setup was executed on the Windows development machine.
The first pass installed the real embedded payload, registered and started the
`HooshiXAgent` service, created the tray task and ARP entry, and enrolled through
the service-owned loopback exchange against a loopback Panel. The Panel observed
proof verification before approval and one claimed request. The service wrote:

- Device: `device-8fSUEjlj0sSL`;
- initial authorization: `auth-ZTAFPu2kDRvj`;
- Gateway: `wss://tunnel.hooshix.test/agent/v1/connect`;
- DPAPI ciphertext at `%ProgramData%\HooshiXAgent\secrets.dpapi` (no plaintext
  token was printed or stored by Setup).

The installed Agent and tray SHA-256 values matched the binaries embedded by the
build. The state directory ACL exposed read/execute to the interactive user and
full control to SYSTEM/Administrators as designed.

A second real Setup pass repaired the installation and enrolled the preserved
identity again under the same account. The Device ID remained
`device-8fSUEjlj0sSL`, the display name changed to
`phase2-real-pc-repaired`, the old authorization became disabled, the new
authorization `auth-QXBKdDW7n6uC` became the only active authorization, and the
Agent config atomically moved to the new authorization/token ID.

The Device was then disabled through the real Panel HTTP/CSRF path. The atomic
projection contained permanent revocations for the Device and both credentials.
Finally the installed CLI delegated `unpair` to the service: the session/config
were cleared, the Ed25519 identity was preserved, status moved to
`pending_config/init`, and the newly installed Windows service was deliberately
left running and ready for production enrollment.

Before the final install, the real uninstaller was also exercised once. It
removed the service, Program Files tree, ProgramData state, tray task and ARP
entry; the final Setup pass then reinstalled from a clean machine state.

### Honest limits of this run

- The Panel was the rebuilt service on `127.0.0.1`; no production data was used.
- The configured test Gateway hostname deliberately had no live WSS listener,
  so this run proves Setup/enrollment/repair/revocation/state ownership, not an
  end-to-end tunneled HTTP request.
- Only one physical Windows PC was available. The automated two-Device tests
  passed, but the two-PC acceptance item below remains open.

## Automated evidence

- Panel tests cover proof-required approval, forged proof, wrong poll secret,
  expiry, one-time claim, CSRF, unauthenticated login return, two Devices under
  one account and same-key repair without a duplicate Device.
- Agent tests cover strict HTTPS exchange validation, oversized/malformed
  responses, listener identity verification, capability/CSRF authentication,
  service-owned credential commit and capability rotation.
- `go vet ./...`, `go test ./...`, Panel tests, TypeScript typecheck and build
  pass from the rebuild worktrees.

## Remaining real Windows gate

Run this only on the designated elevated test machine with a deployed test
Panel/Gateway:

1. Deploy a real test Gateway and Panel under HTTPS/WSS.
2. Install on a second physical PC and verify both Devices appear under the
   same account and can expose independent HTTP services.
3. Disable the first Device and verify its live tunnel/routes fail closed while
   the second Device remains connected.
4. Uninstall with “keep configuration”, reinstall, skip enrollment and verify
   the preserved Device reconnects to the real Gateway.

Do not mark the physical two-PC/Gateway portion complete until those remaining
items are executed and their build version, date and observed results are
appended here.
