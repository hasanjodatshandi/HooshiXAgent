# Edge Agent Runtime — AG-5

**Status:** Current runtime contract (origin AG-5; reconciled through R-13)

The Edge Agent executable is `cmd/agent`.

## Runtime boundary

The Agent owns:

- one unique per-install Ed25519 identity;
- local Agent state/configuration;
- the approved local `local_endpoint_id -> loopback host:port` mapping;
- the outbound WSS/TLS tunnel client;
- protocol-v1 authentication, sequencing, heartbeat responses and bounded stream state;
- final local-target validation/dialing;
- raw TCP proxying between protocol streams and approved loopback services;
- local status/doctor/service/update foundations.

The Agent does **not** implement Control Panel users, accounts, tenants, device CRUD, enrollment-management server logic, endpoint-management APIs, quotas, billing, dashboards or Control Panel persistence.

## State directory

Default state paths are:

```text
Linux:   $XDG_STATE_HOME/hooshixagent or ~/.local/state/hooshixagent
macOS:   ~/Library/Application Support/HooshiXAgent
Windows: %ProgramData%\HooshiXAgent   (service install — the supported channel, ADR-0014)
Windows: %LOCALAPPDATA%\HooshiXAgent  (no service installation present)
```

On Windows the Agent is a machine-wide service (ADR-0014), so its state is machine-wide at `%ProgramData%\HooshiXAgent`, resolved through `FOLDERID_ProgramData` rather than the `ProgramData` environment variable. `DefaultStateDir()` selects that directory whenever a service installation already owns state there, so a CLI invocation follows the service identity instead of creating a second identity under the operator's profile and registering the wrong public key. The per-user path is the fallback only when no service installation owns state.

Every command supports `--state-dir`; packaged service/persistence integration uses this explicit state location without changing the secret ownership model. The owning account on Windows is the service account (LocalSystem), not the interactive desktop user.

The non-secret `config.json` contains the versioned Gateway/identifier/endpoint/update-channel configuration. It never contains the Ed25519 private seed or raw session token.

## Secret storage

Secret state contains only:

- the unique 32-byte Ed25519 seed;
- the configured short-lived session token.

Windows encrypts this payload with DPAPI in the current user's scope before persisting it, with `CRYPTPROTECT_UI_FORBIDDEN` and **without** `CRYPTPROTECT_LOCAL_MACHINE`. This is not machine-scope DPAPI. Under the supported Windows service installation the "current user" is the service account (LocalSystem), so the blob is unprotectable by any other local user; ADR-0014 records exactly what that does and does not protect against. The containing state tree is ACL-restricted to SYSTEM, Administrators and the interactive desktop user by the installer. Unix-like MVP platforms use a private `0700` state directory and a `0600` secret file suitable for headless service accounts. Symlink secret files and overly broad Unix secret-file permissions are rejected.

`status`, `doctor`, logs and runtime evidence never emit the private seed or raw session token.

## External credentials

The external Control Panel remains the issuer/authority for device/session authorization material. The Agent only consumes:

```text
device_id
authorization_id
token_id
short-lived session token
```

The session token is accepted through stdin by `configure`; there is deliberately no token command-line argument that would place it in shell history/process arguments.

## Local target policy

An exposure is local configuration only:

```text
local_endpoint_id -> host:port
```

Allowed MVP hosts:

```text
127.0.0.0/8
::1
localhost
```

The literal `localhost` is dialed only as the fixed loopback candidates `127.0.0.1` and `::1`; arbitrary DNS resolution is not used for local routing.

Rejected targets include LAN/private ranges, link-local/metadata ranges, multicast/wildcard addresses, arbitrary hostnames, URL schemes, file paths, named pipes and Unix sockets.

The Gateway sends only `local_endpoint_id`; it cannot override this local mapping with a raw address.

## CLI

Initialize a persistent identity/state directory:

```bash
hooshix-agent init --state-dir <dir> --json
```

The JSON output contains the public Ed25519 key required by the external registration flow; the private key never leaves local secret storage.

Consume externally issued runtime credentials:

```bash
printf '%s\n' "$SESSION_TOKEN" | hooshix-agent configure \
  --state-dir <dir> \
  --gateway wss://gateway.example/agent/v1/connect \
  --device-id <device-id> \
  --authorization-id <authorization-id> \
  --token-id <token-id> \
  --token-stdin
```

An optional `--ca-file` adds a locally trusted CA for self-hosted/test deployments without disabling certificate verification. Omitting it preserves an already-configured trust anchor rather than clearing it: an absent option means "this request carries no CA file", not "remove the configured one".

### Pairing UI trust anchor

On Windows the service-hosted pairing UI (ADR-0014) is the primary pairing path, so it can set the same trust anchor the CLI does. The pairing payload accepts an optional `ca_file` field and the pairing form renders a `CA file (optional)` input; the form value overrides the payload value when present, and both sit behind the same pairing-capability and per-process CSRF gates as every other pairing field. There is no way to set trust material without them.

- A supplied path replaces the configured trust anchor and is validated before anything is stored: it must be an existing, readable regular file containing at least one PEM certificate that parses into an x509 trust pool. A missing path, a directory, an empty file, non-PEM content, or PEM that holds no certificate (a bare private key, for example) is rejected with an explanatory error and leaves the previous state untouched. The check is a content check, not a path-existence check, because the service account reads this file at session time.
- An absent or empty value preserves the configured trust anchor; pairing never silently drops one.
- After pairing the page reports the effective trust anchor (the configured CA file, or the system trust store when none is set) and pre-fills the input with the configured path.

Clearing a configured trust anchor back to system trust is therefore an explicit edit of `config.json` (`ca_file` removed) or a full `unpair`, never a side effect of pairing.

## Unpair

`unpair` returns the device to the unpaired `pending_config` state:

```bash
hooshix-agent unpair --state-dir <dir>            # keep the device identity
hooshix-agent unpair --state-dir <dir> --reset-identity   # replace it as well
```

It clears exactly the material a pairing installs:

```text
gateway_url, gateway_aliases        (the gateway binding)
ca_file                             (the trust anchor configured for it)
device_id, authorization_id, token_id
the session token                   (in the platform secret store)
```

Two things are deliberately kept:

- **the Ed25519 device identity.** Re-pairing the same device must not silently mint a second identity: the panel would keep authorizing a public key the device no longer holds. `--reset-identity` is the explicit opt-in for a genuinely new identity, and both the help text and the command output distinguish the two cases (`identity_preserved` in `--json`, "preserved" vs "REPLACED" in text). A replacement key is minted by the process that owns the secret store — the Agent service on Windows — inside the same transaction, because a key minted under any other account could not be decrypted by the service.
- **local endpoint mappings.** They are local exposure configuration, not pairing material, and unpair reports how many were preserved rather than dropping them silently.

The operation is all-or-nothing. It runs under the same config lock and rollback journal as `init`/`configure`/`rotate`, so a crash mid-operation cannot leave a cleared config with a live token or the reverse, and it never leaves a transaction journal, a legacy plaintext `token.txt`, or a token record whose config is gone. It is idempotent: on an already-unpaired agent it succeeds and reports that there was nothing to clear.

### Unpair while the service is running

The Windows service runs as LocalSystem and owns a DPAPI **CurrentUser** secret store, which no interactive process can read or rewrite — and a blob minted by the interactive administrator would be undecryptable by the service. Unpair therefore does not touch that state directly:

1. `unpair` probes the state directory for a live pairing endpoint record, challenging the published port for its per-bind listener token (the same check the tray performs before handing over the pairing capability), so a squatter or a stale record is never mistaken for the service.
2. If the service is serving, the command performs the operation **through the service**, using the same authenticated loopback action the pairing page's "Unpair" button uses, behind the same pairing-capability, same-origin and CSRF gates. The service executes it in its own context, which is the only context that can rewrite the secret store.
3. If the machine-wide service owns the directory but is not serving (stopped), the command refuses and states exactly what to do (`hooshix-agent service start`, then run `unpair` again) instead of half-clearing state a running service would disagree with.

The running service then converges by itself: the supervisor watches the config, the secret store and the mutation journal while a tunnel is live, so an operator state change (configure, rotate, unpair) cancels the live loop and re-reads the state within one watch interval. After an unpair the service settles in `pending_config` and stops serving, instead of keeping an authenticated session for a device that is no longer paired, and it no longer reports the change as a terminal failure or requires an SCM restart.

The same action is available from the pairing page ("Unpair this device"), including the optional identity replacement checkbox, and is subject to the same gates as every other mutating form on that page.

Manage approved local mappings:

```bash
hooshix-agent expose add --state-dir <dir> --id local-http-001 --target 127.0.0.1:8080
hooshix-agent expose list --state-dir <dir>
hooshix-agent expose remove --state-dir <dir> --id local-http-001
```

Diagnostics:

```bash
hooshix-agent status --state-dir <dir> --json
hooshix-agent doctor --state-dir <dir>
hooshix-agent doctor --state-dir <dir> --dial-local
```

Run the long-lived tunnel client:

```bash
hooshix-agent run --state-dir <dir>
```

## WSS session and reconnect

The Agent requires a `wss://` URL whose path is exactly `/agent/v1/connect`. Redirects and plaintext `ws://` are rejected.

For each session the Agent:

1. loads the stable local Ed25519 identity and current external session token;
2. opens a TLS-verified WebSocket;
3. sends protocol-v1 `client_hello`;
4. signs the Gateway challenge with the device private key;
5. validates `session_ready` and protocol sequence numbers;
6. responds to heartbeat `ping` messages;
7. accepts only bounded, strictly increasing Gateway-created stream IDs;
8. resolves each `local_endpoint_id` only through local approved configuration;
9. dials only the loopback policy and proxies stream bytes;
10. tears down all active streams when the session ends.

Connection loss triggers bounded exponential reconnect attempts. The delay starts at 1 second and is capped at 30 seconds with bounded jitter. Cancellation or an explicit session-revoked signal stops the loop.

## Resource bounds

Default Agent runtime bounds:

```text
active streams/session       64
queued inbound frames/stream 16
queued inbound bytes/stream   2 MiB
queued inbound bytes/session  8 MiB
local dial timeout             5 s
handshake timeout             10 s
write timeout                 10 s
reconnect delay                1..30 s
```

Protocol frame bounds remain governed by ADR-0007.

## OS persistence foundation

`service-spec` emits a native service definition/command foundation for the current platform:

```bash
hooshix-agent service-spec --state-dir <dir>
```

Persistence integration is documented in `docs/runtime/packaging-and-operations.md`. Linux uses `systemd --user` and macOS uses a LaunchAgent; both remain user-scoped under the ADR-0010 model. **Windows is the exception and runs the `HooshiXAgent` service under the LocalSystem default account, with state at `%ProgramData%\HooshiXAgent`** — the accepted decision recorded in `docs/adr/ADR-0014-windows-agent-service-persistence-and-secret-trust.md`, which supersedes the Windows clauses of ADR-0010. The reason is that a device with no interactive logon session still has to serve its loopback services, which a logon-triggered per-user task cannot do.

The Agent binary's own Windows `service-spec` output and the archive installer `packaging/agent/windows/Install-HooshiXAgent.ps1` both describe and register the accepted service model: `service-spec` emits `sc.exe create HooshiXAgent ... service run-service start= auto` with `sc.exe failure HooshiXAgent resets/restart` recovery (ADR-0014 rollout step R2), and the archive installer now defaults to `C:\Program Files\HooshiXAgent` plus `%ProgramData%\HooshiXAgent` and persists through the binary's own `service install`/`service start` (ADR-0014 rollout step R1). It still unregisters a legacy per-user logon task named `HooshiXAgent` as migration cleanup, so a device upgraded from an early archive release cannot run both persistence models against one device identity. Do not install the archive's Windows persistence on a device that already runs the Agent service.

State and identity survive normal process restart. AG-8 release acceptance additionally verifies native persistence definitions on Linux/macOS/Windows plus fresh-process recovery of the same persisted identity/config/credentials. GitHub-hosted CI does not claim a literal physical runner reboot.

## Update foundation

`update-info` exposes current version/platform/channel information. The Agent package also validates update candidates for:

- matching OS/architecture;
- absolute HTTPS download URL;
- lowercase SHA-256 artifact digest.

Checksummed, attested release packages and previous-binary rollback are implemented. AG-8 verifies platform-matched HTTPS update metadata, package rollback, release checksums and tamper rejection. The Agent still does not autonomously download/apply updates; promotion remains an explicit operator action using verified packages.

## Executable Runtime Gate

`scripts/ci/runtime-gate.sh` now builds both real binaries and verifies locally/deterministically that:

- the real Gateway starts with TLS;
- the real Agent initializes a persistent identity;
- externally issued synthetic runtime credentials are consumed without implementing a Control Panel;
- a loopback service is configured through `local_endpoint_id`;
- the real Agent authenticates to the real Gateway over WSS/TLS;
- a real HTTPS public request traverses Gateway -> protocol-v1 tunnel -> Agent -> loopback HTTP service and returns the response;
- stopping/restarting the Agent with the same state preserves the same identity and restores the tunnel;
- status/log evidence does not expose the session token.

This runtime gate remains the base real-process check. The integrated deterministic route/restart acceptance is defined by `docs/runtime/agent-gateway-e2e-acceptance.md`, while the completed release-resilience coverage is defined by `docs/runtime/security-resilience-release-gate.md`.

## R-8 outbound writer isolation

After session authentication the Agent sends protocol frames through one outbound WebSocket writer goroutine. Control/heartbeat frames use a bounded 32-entry control queue and stream data uses a bounded 2-entry data queue. The writer assigns sequence numbers immediately before encoding and performs every post-authentication WebSocket write, so concurrent stream goroutines cannot create concurrent socket writers or sequence races. Control is preferred whenever both queues have work at a frame boundary; an already-running bounded data-frame write is allowed to finish first and remains subject to the existing write timeout. Authentication handshake frames are still direct single-threaded writes before the session writer starts.

These queues are scheduling bounds, not additional bulk buffering or a capacity claim. Existing stream/session byte budgets, frame-size limits, reconnect behavior, local-target policy, and protocol-v1 semantics remain unchanged.

## R-9 state and config hardening

Agent configuration loading is strict: `config.json` must contain exactly one known-field JSON object and only trailing whitespace after it. A second JSON value, unknown field, symlinked config file, unsupported version, or malformed JSON fails closed. Configuration writers use atomic temporary-file replacement and a bounded cross-process `.config.lock` owner record so `configure` and `expose add/remove` perform read-modify-write under one lock instead of silently overwriting concurrent changes. RA-5 records the owning PID and creation time, never steals a lock whose owner may still be alive, safely reclaims a lock whose owner is proven dead, and retains a conservative age threshold for legacy empty lock files. Malformed/unsafe lock objects fail closed.

Explicit state directories are normalized to absolute paths and reject a filesystem root, the user home directory, an existing state-directory symlink, or an existing non-directory. Writable Agent state is marked with `.hooshix-agent-state` containing the exact versioned ownership marker; an unrelated non-empty directory cannot be silently adopted as Agent state. The private state directory is rechecked before permission changes, and config reads reject symlink/non-regular files. Secret-state JSON is likewise strict about unknown/trailing content. Entropy failures during Ed25519 identity creation or client-nonce generation return normal errors rather than panicking the process.

R-9 does not change the accepted secret-store trust model, loopback policy, WSS protocol, endpoint authority, or Control Panel boundary.

## RA-5 Agent state transaction hardening

`init` and `configure` now mutate `config.json` and the platform secret blob through a local rollback journal under the existing mutation lock. The journal snapshots the previous config/secret state before any semantic write, is published before mutation, and is removed only after the state directory is synchronized. Any ordinary mid-operation failure restores both sides; an interrupted process leaves the journal for the next mutating command to recover before applying its own change. While a complete journal is pending, config and secret read paths fail closed rather than exposing a mixed generation. The journal does not change the config schema, secret payload format, DPAPI ownership model, or external Control Panel contract.

`status` and `doctor` are strictly observational: they load an existing identity instead of creating one, and an uninitialized state directory remains absent. The long-lived `run` path also refuses missing identity/config/credentials instead of manufacturing state. Local invalid configuration, missing/corrupt identity or credentials, invalid local CA configuration, explicit session revocation, and remote WebSocket policy/protocol violations are terminal until operator/control-plane state changes; transport interruption and `try again later` conditions keep the bounded 1..30 second reconnect behavior. Runtime error rendering redacts the active session token wherever known and also scrubs common token/credential/Bearer forms before logging or returning remote-session errors.

`RA-5 Agent state transaction hardening gate` repeatedly exercises rollback after config and secret writes, simulated crash recovery, byte-for-byte diagnostic read-only behavior, stale/live lock ownership, permanent-vs-transient reconnect classification, credential redaction and concurrent mutations under the race detector. The normal platform matrix still executes the complete Agent suite natively on Linux, Windows and macOS.

## RA-6 filesystem trust hardening

Agent state/config/secret reads now open the final file through platform no-follow semantics and verify the opened object is a regular file. Every existing state-directory path component is validated before use: Unix symlink components and Windows reparse points are rejected, including ancestors of an otherwise normal-looking state directory. Unix private state directories/files require effective owner-only permissions (`0700`/`0600`) and permission-setting failures are returned instead of being tolerated; Windows continues to rely on DPAPI in the owning account's user scope plus the explicit install-time state ACL rather than pretending POSIX mode bits are a Windows security boundary. The runtime deliberately does not rewrite state-file DACLs: the ACL applied by the installer before any secret is created is the authoritative one.

These checks do not change the state schema, secret payload format, DPAPI ownership model, local-target authority or Agent-to-Gateway protocol. The RA-6 CI matrix runs adversarial filesystem tests on Unix and native junction tests on Windows.
