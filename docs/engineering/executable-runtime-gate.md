# HooshiXAgent Executable Runtime Gate

**Status:** Normative

Unit tests, integration tests, static analysis, compilation, and smoke tests are necessary where applicable, but they do not replace execution of a capability once that capability is runnable.

## 1. Trigger

Whenever a capability becomes runnable, the real capability MUST be executed before the leaf can PASS.

Examples of runtime-gate triggers include:

- Gateway process starts;
- an HTTP/API route becomes functional;
- Agent authenticates;
- authorization/enrollment material can be consumed;
- a tunnel session opens;
- stream multiplexing works;
- a local service exposure command works;
- public ingress routes;
- an OS service installs;
- reboot persistence works;
- an updater can apply an update;
- a deployment package/Compose stack can start.

If runtime testing is technically possible but is skipped, the applicable leaf cannot PASS.

## 2. Runtime evidence requirements

Runtime evidence must identify:

- the executable/capability exercised;
- environment and dependency setup relevant to the result;
- command or reproducible procedure used;
- expected positive behavior;
- applicable negative/failure behavior;
- observed result;
- restart/reconnect/persistence behavior when part of the leaf;
- secrets/PII handling;
- any checks that were Not run or Partially verified.

A log statement claiming startup is not a substitute for exercising the capability.

## 3. Tunnel runtime example

When the Agent/Gateway path becomes runnable, an applicable gate is:

```text
start approved local test service
start real Gateway
start real Edge Agent
apply deterministic authorized device/session/endpoint fixture
establish authenticated Agent session
send a real public/staging request through the Gateway
verify the approved local service receives it
compare expected local/public response behavior
interrupt the connection
verify reconnect/recovery
```

Mocks may stand in for the separate external Control Panel contract when the active leaf permits it, but mocks do not replace the real Agent and Gateway processes when those processes are the capability under test.

## 4. Service/deployment runtime example

When a service or deployment package becomes runnable, applicable evidence includes:

```text
start the real packaged process/deployment
exercise readiness/health
exercise at least one real critical path
exercise an applicable invalid/failure path
restart the process/deployment
verify expected recovery/persistence
```

## 5. Completion rule

The following alone are insufficient completion evidence when a real runtime gate applies:

```text
code exists
it compiles
unit tests pass
integration tests pass
static/security scans pass
PR is open
CI is green
PR is approved
```

Completion still requires the applicable real runtime evidence plus the project's PR/merge/post-merge requirements.

## 6. Non-runnable leaves

A governance/documentation-only leaf that introduces no executable capability may mark the Executable Runtime Gate as `Not applicable`, with the reason recorded in evidence.

`Not applicable` MUST NOT be used when a real capability is runnable and technically testable.

## 7. Registered runtime-gate gaps

A gap is an approved, explicitly recorded place where a runnable capability is not executed by any gate. Gaps MUST be listed here with their reason and their compensating coverage. A gap is tracked debt, never permission to claim runtime coverage: while a gap is open, the affected capability MUST be reported as `Not run`.

G1 and G2 below are retained after closure for traceability: the capability each covered is now executed by a real gate, and both gates are wired into the automated CI chain. Their CI evidence appears on the next Windows CI run; because no workflow run has been observed since the wiring landed, neither capability may be reported as CI-`Passed` until that run exists.

### G1 — Windows desktop distribution (Setup.exe, tray, Agent service) — closed as a defined gate and wired into CI

`scripts/ci/windows-service-install-smoke.ps1` is the gate for the accepted Windows persistence path (ADR-0014 rollout step R4). It requires an elevated Windows host, fails closed rather than skipping when it cannot run, and then executes the real capability rather than its build: it builds or accepts the real `HooshiXAgent-Setup.exe`, runs the real installer, asserts the observable accepted model, exercises SCM restart-on-failure, and finally asserts that the installed uninstaller removes everything again.

Asserted while installed:

- `hooshix-agent.exe`, `hooshix-agent-tray.exe` and `uninstall.exe` under `Program Files\HooshiXAgent`;
- the `HooshiXAgent` service `AUTO_START`, `SERVICE_START_NAME: LocalSystem`, image path carrying `service run-service` and no `schtasks`/`ONLOGON`;
- `sc.exe qfailure` restart-on-failure at the accepted 5000 ms;
- the interactive-user service DACL limited to query-status/start/stop, with SYSTEM and Administrators kept in control;
- the `%ProgramData%\HooshiXAgent` state tree with its ownership marker, and a non-inheriting `pairing.capability` ACL that grants neither `Everyone` nor `BUILTIN\Users`;
- `status.json` published by the running Agent supervisor and the loopback pairing listener actually listening;
- the Windows uninstall (ARP) entry, and the tray auto-start task when an interactive desktop user was resolved (the installer's documented headless downgrade is accepted otherwise).

Exercised and asserted after removal:

- a forced termination of the service process, followed by an observed SCM restart of the service and a republished loopback pairing listener;
- uninstall leaving no service registration, no running agent process, no install directory, no ARP entry, no tray task and no state tree.

Two limits must be preserved in any evidence that cites this gate:

- **It is wired into CI, its gate step has now completed green on a hosted Windows runner, and the job that runs it has never been green.** The `windows-distribution-build` job in `.github/workflows/ci.yml` invokes `scripts/ci/windows-service-install-smoke.ps1` after its build-integrity steps, passing the distribution it already built via `-SetupExe` rather than rebuilding it. The gate fails closed and never skips, so a hosted Windows run that could not install, start, restart or uninstall the service fails the job by name. Earlier hosted runs failed inside the gate's own assertions (first the icon-tinting step it depends on, then an `[bool]` parameter cast applied to a registry `PSNoteProperty` in the ARP block). Run 38344596038 on 2026-10-13 (commit `b3b29a7`, Windows Server 2025) is the first hosted execution that ran to completion: its step printed `Windows service distribution install / run / restart / uninstall gate: PASSED`, so the install/start/restart/uninstall behaviour it exists to prove has now been observed on a runner. That job was still red overall, because the Connect GUI gate step that follows it failed, so a job-level `Passed` claim still waits for an observed green `windows-distribution-build` run; the recorded elevated real-machine run of 2026-09-17 remains corroborating evidence, not a substitute for it.
- **It does not reboot the host.** Reboot persistence is evidenced as SCM automatic-start configuration plus an observed SCM restart-on-failure after a forced process termination, never as a literal physical OS reboot.

`HooshiXAgent-Setup.exe` is the supported, published Windows distribution channel and the only installer that installs the accepted Windows service model (`docs/adr/ADR-0014-windows-agent-service-persistence-and-secret-trust.md`), so this gate covers the accepted Windows persistence path itself, not a convenience extra. The elevated precondition is why it is not run by an unprivileged runner: `cmd/hooshix-setup` resolves the interactive desktop user through WTS (`interactiveUser()`) and the flow mutates machine state — a Windows service, a per-user logon scheduled task for the tray, the machine ARP entry, `Program Files` binaries and `ProgramData` ACLs.

Remaining non-gate coverage (none of it exercises `Setup.exe`):

- the distribution must still build from a clean checkout, with no manual resource steps (`windows-distribution-build`);
- the Agent package install / rollback / uninstall lifecycle is executed on `windows-latest` by `scripts/ci/agent-install-smoke.ps1`. That smoke runs the archive installer with `-NoPersistence`, so it never starts the service. It does now assert that the installed binary's own `service-spec` describes the accepted `sc.exe create HooshiXAgent`/`start= auto` model and rejects `schtasks`/`ONLOGON`, and it covers checksum refusal, destructive-path refusal and transactional rollback — but the service install/start/stop path itself is covered only by the gate above;
- `cmd/hooshix-agent-tray` has no separate runtime procedure and stays allowlisted below; the tray is a desktop UI affordance, not Agent persistence (ADR-0014 clause 6).

### Connector bundle client — both closed

The RDP connect path ships two executables built from the same connector library (`internal/connector`), and they are recorded separately because their gates run on different CI legs.

**`cmd/hooshix-connector` — closed: executed by this gate.** `scripts/ci/runtime-gate.sh` builds the binary and runs `TestRealConnectorExecutableCarriesPrivateTCPBytes` (`tests/integration/private_connector_e2e_test.go`) through `fail_if_no_tests`, so an empty selection is a failure, never a green no-op. The test starts a real Gateway handler over TLS and a real Agent runner, then launches the built executable as a child process with exactly the inputs an operator has: a Panel-shaped `hx1.` bundle (`panelBundle` mirrors `buildConnectorBundle`), `-listen` and a private `-ca-file` trust anchor. Asserted:

- bytes round-trip `echo:executable` through the loopback port, which only happens if the process parsed the bundle, trusted the anchor and opened the authenticated connector flow through the Agent;
- a malformed bundle exits with the CLI usage status 2 and its diagnostic on stderr, before any socket is opened;
- when the process is asked to exit it releases the loopback port, so a later grant can bind it. On non-Windows hosts that is SIGTERM plus a clean status; on Windows `os/exec` cannot deliver a signal, so only the kill path is asserted there and graceful shutdown is reported as verified on Linux/macOS.

`scripts/ci/go-quality.sh` builds and exports `HOOSHIX_CONNECTOR_BINARY` alongside the Agent and Gateway binaries for the same reason it already does for those two: `tests/integration` fails closed in CI when the variable is missing, so the shipped executable cannot be quietly skipped out of `go test ./...`.

**`cmd/hooshix-connect` (the Windows GUI) — G2, closed as a defined gate and wired into CI.** `scripts/ci/connect-gui-runtime.ps1` is the gate for the GUI process. The GUI is a Win32 message loop built with `-H windowsgui`: it has no console and cannot start on Linux or macOS, so it stays allowlisted in `scripts/ci/runtime-gate.sh` on the Unix leg and is executed on the Windows leg instead, in the `windows-distribution-build` job beside the ADR-0014 gate. It is fail-closed and never skips: it refuses to run on a non-Windows host, on a session without an interactive desktop, or when a `hooshix-connect` process or the `127.0.0.1:13389` listener is already present, and it declares itself system DPI aware in the same way the artifact's manifest does, then fails if the process DPI and the window DPI disagree (the signature of a virtualized observer measuring itself instead of the app).

Asserted by launching the built artifact from a throwaway directory (the saved bundle lives beside the executable, so the gate must not run against `dist/`) and driving the real window through Win32 messages — `WM_SETTEXT`, `WM_PASTE`, `BM_CLICK`, `WM_CLOSE`, `EnumChildWindows`, `GetDlgCtrlID`, `GetClientRect` — never through internal state. Every observation of an edit control goes through a direct `WM_GETTEXT`; cross-process `GetWindowText` reads the window-text cache, and an edit the gate pasted into has an empty cache, so the assertion that the app cleared the bundle would pass while proving nothing:

- a first run with no cfg shows the paste area, the caption, the status and hint lines, the full window shape, writes no file beside the exe and binds no port;
- Connect with an empty paste area raises the modal refusal, and a malformed bundle (`hx1.` plus illegal base64) lands the status on `failed` with the parse diagnostic and opens no socket;
- a valid fixture bundle puts the status on `listening on 127.0.0.1:13389 (tcp)`, clears the paste area, writes `hooshix-connect.cfg` beside the exe (`version=1`, `saved_at=`, `bundle=` and neither the `hx1.` prefix nor a single byte of the token), collapses the window to the compact shape with the reveal button titled with the saved date, and really binds the loopback port — that probe runs last in the scenario because a dial creates a flow and rewrites the message line the earlier assertions just read;
- a client that dials that port and dies is reported on the status area as `Last client ended` naming `dial connector gateway` while the session stays `listening`, which is the only automated proof that the line an operator reads tracks real flow events;
- Disconnect reports `stopped` and releases the port, closing the window exits the process and releases it again, and reconnecting from the remembered bundle needs no re-paste — including a relaunch that starts in the compact shape and connects with an empty paste area;
- a forged, unreadable cfg puts the paste area back, explains itself once through the `cannot use a saved bundle` dialog, still connects from a pasted bundle, and replaces the stale store.

The fixture credential is sealed into a repository-side bundle pointing at `wss://127.0.0.1:1/connector/v1/connect`, so the gate needs no network, no Gateway and no grant, and the sealed value's whole lifetime is the run that is deleted in the gate's `finally`.

Three limits must be preserved in any evidence that cites this gate:

- **It is wired into CI, it has passed on a real desktop, and its first hosted execution has now been observed: a red one, inside the gate itself.** The gate ran end-to-end on the elevated operator machine on 2026-10-13 at 192 DPI and exited 0 with its workspace removed, against the artifact the Panel serves: the build from clean `97faf91` (7,836,672 bytes, sha256 `7b17443de16ff27e6865b55ccc4d34cd7119027ea6318f14015bbcad57ee6dc8`) passed both as `dist/hooshix-connect.exe` and as the file downloaded back through `https://panel.hooshix-agent.ir/download/hooshix-connect.exe`, so the bytes operators receive are the bytes this gate validates. Run 38344596038 on 2026-10-13 (commit `b3b29a7`) executed the gate under PowerShell 7 on a hosted runner for the first time: it built and verified the artifact, drove S1 and S2, reached `listening on 127.0.0.1:13389 (tcp)` in S3, and then reported that a successful Connect had written no `hooshix-connect.cfg` while listing the file it could see as `39\hooshix-connect.cfg`. Two of the gate's own assumptions were false on a runner and each was fixed by removing the assumption, never the assertion. `$env:TEMP` on a GitHub Windows runner is an 8.3 path (`C:\Users\RUNNER~1\AppData\Local\Temp`) while `Get-ChildItem` reports long `FullName` values, so trimming `$Workspace.Length + 1` characters cut the wrong prefix; the file list is now the leaf names beside the exe, directories included because the app must not create any. And `EnumWindows` returns the main frame the moment `CreateWindowExW` returns, before the app has created a control (it builds without `WS_VISIBLE` and shows only after applying the shape), so a relaunch could be measured mid-startup as `the window has no control with id 106`; the gate now waits for the visible frame as the app's own readiness signal. The fixed gate passes on the operator desktop with `$env:TEMP` forced to an 8.3 short path, which is how the runner shape was reproduced here, and with a normal long path. A green `windows-distribution-build` run has still not been observed, so this capability must not be reported as CI-`Passed`.
- **It does not prove that a remote desktop session reaches a target.** The fixture bundle points at a port nothing listens on, so the gate covers the GUI's own listener, status machine, persistence and teardown. The path from the tunnel into a Windows session is evidenced by the manual runs below and by the Agent-side `stream open`/`stream finished` records, not by this gate.
- **It does not read pixels.** It asserts which controls exist, what text they hold, and their client height; it cannot see clipped glyphs. The hint-row clipping defect was found by capturing the window, and `TestHintTextFitsItsStatic` is what keeps it from coming back.

Coverage that runs alongside the gate:

- `internal/connectgui` holds the entire state machine (bundle parse → loopback bind → serve → disconnect → shutdown), is platform-neutral, and is executed on every OS in `go test ./...`; its `ButtonsFor`/`StatusLabel`/`RDPTarget`/`IdleMessage` decisions are asserted there, so the only code left in `cmd/hooshix-connect` is window creation, message pumping, and the DPAPI call that seals a saved bundle.
- The saved-bundle file (`hooshix-connect.cfg` beside the executable) is policy in `internal/connectgui/bundlestore.go`, which runs on every OS in CI: strict parsing that refuses unknown, repeated or unreadable lines, bounded 8 KiB reads, atomic publish by rename, a round-trip through an injected `Protector`, and the assertion that the file holds no readable credential. Only `CryptProtectData`/`CryptUnprotectData` live in `cmd/hooshix-connect`, tested on Windows.
- `scripts/build-connect.ps1` is a fail-closed build gate for the artifact shape (`.rsrc` section present, PE subsystem 2), so a binary that would flash a console window instead of a UI never reaches the Panel download route.
- The manual elevated-machine run on 2026-10-10 drove the real window — paste a valid bundle, connect, `mstsc` against the published port, revoke, disconnect, close — and is corroborating evidence, not a substitute for a gate.
- A second manual run on 2026-10-12 from a separate physical machine took the released `hooshix-connect.exe` along the same path: the bundle connected, the loopback listener came up, `mstsc` reached the target and Windows presented its own credential prompt, which the operator's account passed. The session was then arbitrated away by the target's client-SKU single-interactive-session licence (`docs/runtime/remote-desktop.md`), so this run evidences HooshiX's transport through Windows authentication and stops exactly where Windows takes over.
- A third run later the same day, against the build published after `301fd0c` (visible `mstsc` window, honest flow status line, single-client guard), produced a remote desktop session on that machine that the operator kept working in. The Agent corroborates it from its own side: `msg="stream open"` and `msg="stream finished"` for `endpoint_id=rdp-001` with `mode=tcp` and non-zero `bytes_sent`/`chunks`. Human runtime evidence for the GUI is therefore complete and it covers every behaviour the fixes claim; the automation that was missing was a CI leg launching the executable, and `scripts/ci/connect-gui-runtime.ps1` is it.

- A fourth manual run on 2026-10-12 drove the saved-bundle path with the shipped `hooshix-connect.exe`, reading the live window through Win32 (`EnumChildWindows`, `GetWindowRect`, `WM_PASTE`, `BM_CLICK`) rather than trusting the build: with no cfg the window has the paste area, pasting a `hx1.` bundle and pressing Connect cleared the edit, wrote `hooshix-connect.cfg` beside the exe, and the same window collapsed to the compact shape with the edit and its caption hidden and one **Use a different bundle (last saved 2026-10-12)** button in their place; pressing that button restored the paste area. The cfg held no `hx1.` prefix and no token bytes, and a file sealed by .NET `ProtectedData` opened in the Go binary (and the reverse), which pins the DPAPI format rather than this program's own round-trip. A stale cfg from another account leaves the paste area up and reports why once, after the first paint. This is corroborating evidence for the human path; `scripts/ci/connect-gui-runtime.ps1` asserts the same window behaviour automatically on every Windows CI run.
- Reading that window's pixels, not just its controls, then found a defect no assertion could see: the compact shape's hint is longer than the full shape's, both rows shared a 44-DIP static, and a `STATIC` clips silently, so the last sentence lost its lower half. The fix sized the hint row from the capture (four lines at the 16.7 DIP pitch the render actually uses) and `TestHintTextFitsItsStatic` now refuses a hint longer than its box. A fifth run captured both shapes again: the full frame is 401 px and the compact 295 px, and in both the hint's fourth line ends above the frame edge with the whole sentence visible. The same capture confirms a first run with no cfg writes nothing to disk.

G2 is therefore closed as a defined gate and wired into CI: the `windows-distribution-build` job builds `hooshix-connect.exe` through `scripts/build-connect.ps1`, verifies the artifact is present and plausibly sized and prints its SHA-256, then runs `scripts/ci/connect-gui-runtime.ps1 -ConnectExe dist\hooshix-connect.exe` after the ADR-0014 service gate in the same job. Nothing about the GUI process is reported as CI-`Passed` until a hosted run of that job is green.
