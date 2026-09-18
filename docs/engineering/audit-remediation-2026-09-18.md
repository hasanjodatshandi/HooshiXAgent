# Audit remediation receipt — 2026-09-18

Scope: the local Agent, Gateway, Windows tray, contracts, installers and release
checks. This receipt describes the current working tree, not a committed or
published release. Existing unrelated changes were preserved. The external
Control Panel was not audited or changed.

## Corrected defects

| Area | Correction | Verification |
| --- | --- | --- |
| Tray click delivery | Icon, tooltip and balloon updates no longer set `NIF_MESSAGE` with a zero callback, which erased the registered click handler. | `TestIconUpdatesPreserveClickCallback` covers all three modification paths. |
| Tray keyboard events | Corrected `NIN_KEYSELECT`; balloon-show events no longer open the menu. Failed v4 negotiation reports legacy fallback, not broken click delivery. | `TestTrayMouseAndKeyboardEventsQueueMenu`, `TestApplyNotifyVersionReportsLegacyFallback`. |
| Metadata outages | Stale/unavailable authorization metadata fails closed but uses retryable WebSocket closure rather than permanently revoking the Agent. Real revocations remain terminal. | Real-process long-outage recovery test, Gateway tests. |
| HTTP HEAD | Preserve response headers without treating HEAD Content-Length as a body to transfer. | Real tunnel HEAD regression. |
| SSE | Flush headers and event writes, including content types with parameters. | Real tunnel SSE first-event regression. |
| Resume timeout | Bound authentication/resume by the configured handshake deadline. | `TestResumeHandshakeHasItsOwnDeadline`. |
| HA health | The actual primary worker updates the health machine exposed by the runner; standby workers have independent machines. | `TestHAHealthTracksRealAuthenticatedPrimary`. |
| HA failure isolation | A gateway-local permanent failure does not terminate healthy siblings; device-wide revocation still does. | `TestPermanentAliasFailureDoesNotCancelHealthyPrimary`. |
| Protocol compatibility | Negotiate resume proof through a WebSocket subprotocol; baseline v1 peers retain the baseline strict handshake shape. No unnegotiated resume is accepted. | Legacy/new Agent and Gateway negotiation tests; ADR-0015. |
| Multiplexing | A full stream queue terminates only that stream instead of blocking the shared reader for two seconds. | Stream isolation test; large-request streaming passed ten repetitions. |
| Windows first start | Initialize the state identity and pairing capability before the logger/listener. Persistent archive installation establishes the state access policy first. | DPAPI bootstrap/restart test; archive installer lifecycle smoke. |
| Windows service recovery | Reset the failure count after 86,400 seconds, not one second. | Installed dependency documentation confirms seconds; build and service package tests pass. Native SCM policy application remains an isolated-host validation item. |
| Release workflow | Check out the selected immutable release SHA before finalization scripts; pass dispatch input through an environment variable. | Release architecture tests. |
| Local quality gates | Restrict source discovery to non-ignored Git files, preserve test failures and require actual passing tests. Join multiline PowerShell CLI output before matching. Compare HTTP header names case-insensitively. | Runtime/E2E gates, Windows archive smoke, real public-edge gate. |
| Secret scan fixture | Narrowly allow the deterministic synthetic contract fixture, with Windows/Unix path matching. | Gitleaks `internal` directory scan reports no findings. |

## Validation completed

- `go test ./... -count=1 -timeout=180s` passed on Windows.
- Race detector passed for Agent, Gateway, Tray, contract and Windows service packages.
- `go vet ./...` and `go mod verify` passed.
- Agent cross-build passed for Linux, Windows and macOS, on amd64 and arm64.
- Executable runtime and Agent/Gateway E2E gates passed, including real HEAD,
  SSE and recovery after a metadata outage longer than the heartbeat interval.
- Windows archive clean-install, tamper rejection, rollback and uninstall
  smoke passed in disposable test directories, without replacing the live service.
- The real Docker/Caddy public-edge gate passed: two approved hosts reached
  distinct local endpoints, route-less authority returned 404, unknown TLS
  authority was denied, operational endpoints stayed private, HSTS/nosniff
  were present, and Caddy-to-Gateway certificate verification remained enabled.
  This particular gate uses static compatibility metadata, not the external
  production Control Panel.
- Local Semgrep scan passed its two configured rules; this is not a general
  security certification.
- `scripts/build-setup.ps1` successfully built `dist/HooshiXAgent-Setup.exe`,
  `dist/hooshix-agent.exe` and `dist/hooshix-agent-tray.exe` with local version
  `v0.0.0-local-fixes`.

## Remaining release boundaries

1. `govulncheck ./...` is inconclusive: the official vulnerability database
   returned HTTP 403. A successful scan is required before release; failure to
   fetch the database does not establish that dependencies are vulnerability-free.
2. The running installed tray still uses the previous executable in Program
   Files. This work built the replacement package but did not install it or
   change the live pairing state. A real desktop click after installation has
   not been observed; the click regression is verified through automated tests.
3. Full Setup/SCM install, restart-on-failure, reboot and uninstall validation
   must run on an isolated Windows host. The machine-wide destructive service
   lifecycle gate was not run against the user's existing installation.
4. No signed release, exact-commit remote CI, production deployment, external
   Control Panel integration certification or production load/SLO certification
   was performed. The locally built installer is not a signed release artifact.
5. The existing large Agent/Gateway orchestration packages retain architectural
   coupling. The concrete HA health and failure-isolation defects were fixed;
   this is not a claim that every architectural concern has been eliminated.
   Further decomposition should preserve the tested protocol and ownership
   boundaries, rather than replace the implementation wholesale.

Conclusion: the listed code defects have corrections and the above local
checks passed, but unrestricted production approval is withheld until the
remaining release boundaries are verified.
