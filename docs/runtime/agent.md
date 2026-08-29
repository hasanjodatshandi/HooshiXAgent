# Edge Agent Runtime — AG-5

**Status:** Current AG-5 runtime contract

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

Default per-user state paths are:

```text
Linux:   $XDG_STATE_HOME/hooshixagent or ~/.local/state/hooshixagent
macOS:   ~/Library/Application Support/HooshiXAgent
Windows: %LOCALAPPDATA%\HooshiXAgent
```

Every command supports `--state-dir` so service/packaging work can provide an explicit install location later.

The non-secret `config.json` contains the versioned Gateway/identifier/endpoint/update-channel configuration. It never contains the Ed25519 private seed or raw session token.

## Secret storage

Secret state contains only:

- the unique 32-byte Ed25519 seed;
- the configured short-lived session token.

Windows encrypts this payload with DPAPI for the current user before persisting it. Unix-like MVP platforms use a private `0700` state directory and a `0600` secret file suitable for headless service accounts. Symlink secret files and overly broad Unix secret-file permissions are rejected.

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

An optional `--ca-file` adds a locally trusted CA for self-hosted/test deployments without disabling certificate verification.

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

AG-5 does not install the service. Installer/service installation, signing, packaging and deployment belong to AG-7.

State and identity survive normal process restart. Full OS reboot acceptance remains a later AG-8 release gate.

## Update foundation

`update-info` exposes current version/platform/channel information. The Agent package also validates update candidates for:

- matching OS/architecture;
- absolute HTTPS download URL;
- lowercase SHA-256 artifact digest.

AG-5 does not download/apply updates or define release signing/rollback. Those belong to AG-7/AG-8.

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

This remains the AG-5 local runtime gate. The integrated deterministic test-route and Agent/Gateway restart acceptance is now defined separately by AG-6 in `docs/runtime/agent-gateway-e2e-acceptance.md`; broader release resilience remains AG-8 work.
