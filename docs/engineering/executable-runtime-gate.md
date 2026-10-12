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

G1 below is retained after closure for traceability: the capability it covered is now executed by a real gate, and that gate is wired into the automated CI chain. The gate's CI evidence appears on the next Windows CI run; because no workflow run has been observed since the wiring landed, the capability must not be reported as CI-`Passed` until that run exists.

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

- **It is wired into CI, and hosted Windows runs have been observed, but none of them has passed the gate yet.** The `windows-distribution-build` job in `.github/workflows/ci.yml` invokes `scripts/ci/windows-service-install-smoke.ps1` after its build-integrity steps, passing the distribution it already built via `-SetupExe` rather than rebuilding it. The gate fails closed and never skips, so a hosted Windows run that could not install, start, restart or uninstall the service fails the job by name. The observed runs failed inside the gate's own assertions (first the icon-tinting step it depends on, then an `[bool]` parameter cast applied to a registry `PSNoteProperty` in the ARP block), so the install/start/restart/uninstall behaviour it exists to prove has still never completed on a runner. Until a green Windows CI run of that job is observed, automated CI evidence for Windows service installation and Windows Agent reboot/persistence remains `Not run`. A `Passed` claim still requires that observed run; the recorded elevated real-machine run of 2026-09-17 is corroborating evidence, not a substitute for it.
- **It does not reboot the host.** Reboot persistence is evidenced as SCM automatic-start configuration plus an observed SCM restart-on-failure after a forced process termination, never as a literal physical OS reboot.

`HooshiXAgent-Setup.exe` is the supported, published Windows distribution channel and the only installer that installs the accepted Windows service model (`docs/adr/ADR-0014-windows-agent-service-persistence-and-secret-trust.md`), so this gate covers the accepted Windows persistence path itself, not a convenience extra. The elevated precondition is why it is not run by an unprivileged runner: `cmd/hooshix-setup` resolves the interactive desktop user through WTS (`interactiveUser()`) and the flow mutates machine state — a Windows service, a per-user logon scheduled task for the tray, the machine ARP entry, `Program Files` binaries and `ProgramData` ACLs.

Remaining non-gate coverage (none of it exercises `Setup.exe`):

- the distribution must still build from a clean checkout, with no manual resource steps (`windows-distribution-build`);
- the Agent package install / rollback / uninstall lifecycle is executed on `windows-latest` by `scripts/ci/agent-install-smoke.ps1`. That smoke runs the archive installer with `-NoPersistence`, so it never starts the service. It does now assert that the installed binary's own `service-spec` describes the accepted `sc.exe create HooshiXAgent`/`start= auto` model and rejects `schtasks`/`ONLOGON`, and it covers checksum refusal, destructive-path refusal and transactional rollback — but the service install/start/stop path itself is covered only by the gate above;
- `cmd/hooshix-agent-tray` has no separate runtime procedure and stays allowlisted below; the tray is a desktop UI affordance, not Agent persistence (ADR-0014 clause 6).

### Connector bundle client — one closed, one open

The RDP connect path ships two executables built from the same connector library (`internal/connector`), and they are recorded separately because only one of them has a runnable automated gate.

**`cmd/hooshix-connector` — closed: executed by this gate.** `scripts/ci/runtime-gate.sh` builds the binary and runs `TestRealConnectorExecutableCarriesPrivateTCPBytes` (`tests/integration/private_connector_e2e_test.go`) through `fail_if_no_tests`, so an empty selection is a failure, never a green no-op. The test starts a real Gateway handler over TLS and a real Agent runner, then launches the built executable as a child process with exactly the inputs an operator has: a Panel-shaped `hx1.` bundle (`panelBundle` mirrors `buildConnectorBundle`), `-listen` and a private `-ca-file` trust anchor. Asserted:

- bytes round-trip `echo:executable` through the loopback port, which only happens if the process parsed the bundle, trusted the anchor and opened the authenticated connector flow through the Agent;
- a malformed bundle exits with the CLI usage status 2 and its diagnostic on stderr, before any socket is opened;
- when the process is asked to exit it releases the loopback port, so a later grant can bind it. On non-Windows hosts that is SIGTERM plus a clean status; on Windows `os/exec` cannot deliver a signal, so only the kill path is asserted there and graceful shutdown is reported as verified on Linux/macOS.

`scripts/ci/go-quality.sh` builds and exports `HOOSHIX_CONNECTOR_BINARY` alongside the Agent and Gateway binaries for the same reason it already does for those two: `tests/integration` fails closed in CI when the variable is missing, so the shipped executable cannot be quietly skipped out of `go test ./...`.

**`cmd/hooshix-connect` (the Windows GUI) — G2, open.** The GUI is a Win32 message loop built with `-H windowsgui`: it has no console, cannot start on Linux or macOS, and no CI job launches it. It is allowlisted in `scripts/ci/runtime-gate.sh` for the same structural reason as the tray and setup binaries, and while this gap is open the GUI process itself MUST be reported as `Not run`.

Compensating coverage, none of which executes `hooshix-connect.exe`:

- `internal/connectgui` holds the entire state machine (bundle parse → loopback bind → serve → disconnect → shutdown), is platform-neutral, and is executed on every OS in `go test ./...`; its `ButtonsFor`/`StatusLabel`/`RDPTarget` decisions are asserted there, so the only code left in `cmd/hooshix-connect` is window creation and message pumping.
- `scripts/build-connect.ps1` is a fail-closed build gate for the artifact shape (`.rsrc` section present, PE subsystem 2), so a binary that would flash a console window instead of a UI never reaches the Panel download route.
- The manual elevated-machine run on 2026-10-10 drove the real window — paste a valid bundle, connect, `mstsc` against the published port, revoke, disconnect, close — and is corroborating evidence, not a substitute for a gate.
- A second manual run on 2026-10-12 from a separate physical machine took the released `hooshix-connect.exe` along the same path: the bundle connected, the loopback listener came up, `mstsc` reached the target and Windows presented its own credential prompt, which the operator's account passed. The session was then arbitrated away by the target's client-SKU single-interactive-session licence (`docs/runtime/remote-desktop.md`), so this run evidences HooshiX's transport through Windows authentication and stops exactly where Windows takes over. G2 still requires an automated CI leg.

Closing G2 requires a Windows CI leg that launches `hooshix-connect.exe` and asserts its observable behaviour (status/message text, the loopback listener appearing and disappearing, the process exiting when its window closes) rather than its build; the technique is already proven on a real desktop, and the harness belongs in the `windows-distribution-build` job beside the ADR-0014 gate.
