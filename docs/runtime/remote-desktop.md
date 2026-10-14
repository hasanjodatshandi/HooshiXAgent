# Remote Desktop (RDP) over the tunnel

Audience: the operator who wants to reach a paired Agent machine with Windows
Remote Desktop from another machine, without opening any public RDP port.

RDP is not an Agent feature with an on/off switch. It is the private Connector
path of ADR-0017 (`docs/adr/ADR-0017-private-connector-tcp-and-rdp.md`) with one
extra label: a private TCP endpoint whose `application_protocol` is `rdp`. The
Agent contributes only a loopback mapping; admission is decided by Windows, the
Panel grant, and the Gateway. Nothing in the Agent, the pairing page, the tray
or `Setup.exe` enables or disables Remote Desktop on the machine, and the Agent
never touches the Windows `fDenyTSConnections` setting.

The accepted two-machine run is recorded in
`docs/engineering/phase-4-private-tcp-rdp-acceptance.md`.

## Pieces and who owns them

| Piece | Where it lives | Who changes it |
| --- | --- | --- |
| "Allow remote connections" | Windows on the Agent machine | Operator, in Windows |
| `rdp-001 → 127.0.0.1:3389` mapping | Agent state `config.json` | Pairing page, section 3 |
| Private endpoint (`protocol tcp`, `exposure private`, `application_protocol rdp`) | Panel DB → published metadata | Panel dashboard |
| Connector grant (one-time token, TTL 1–60 min, ≤16 connections) | Panel DB → published as digest only | Panel dashboard |
| Connect bundle (`hx1.…`, one string carrying the whole grant) | Panel grant page | Panel dashboard |
| Loopback listener `127.0.0.1:13389` | `hooshix-connect.exe` (GUI) or `hooshix-connector` (CLI) on the client machine | Operator |

## Prerequisites

- The Agent is paired and its Tunnel status (section 2 of the pairing page)
  reads `connected`. An offline Device admits no flow.
- DNS: `panel.hooshix-agent.ir` **and** `edge.hooshix-agent.ir` both resolve.
  `edge` is the only published Gateway hostname; the earlier `tunnel` spelling is no
  longer fronted by Caddy (some networks drop that literal name from DNS answers),
  so an Agent or Connector still pointing at it fails before any HooshiX logic runs.
  Check with `Resolve-DnsName edge.hooshix-agent.ir`.
- Windows on the Agent machine allows remote connections
  (System Properties → Remote → *Allow remote connections to this computer*),
  and the account you log in with has RDP permission. Until this is true the
  tunnel works and RDP does not.
- **Nobody is signed in at that machine's console.** Windows client SKUs permit
  only one interactive session; see *One interactive session at a time* below.
- `hooshix-connect.exe` on the machine you connect **from**. It is not installed
  by `Setup.exe`; download it from the Panel (`/download/hooshix-connect.exe`) or
  build it with `powershell -File scripts\build-connect.ps1`. The command-line
  Connector (`go build -o dist\hooshix-connector.exe ./cmd/hooshix-connector`)
  does the same job without a window.
  Since 2026-10-14 the Panel serves `sha256`
  `6a9df263b00d680db9dc52b66fa60fe5ffa8314ab902a424bde5a7e86aece5b8` (7,836,672
  bytes), the build whose on-screen hint names Revoke as the way to end the
  tunnel; like the 2026-10-13 build it saves the bundle beside itself, so a
  second run needs no re-paste. Verify what you downloaded with
  `certutil -hashfile hooshix-connect.exe SHA256`; an older digest still connects,
  but it asks for the bundle on every run.

## Enable

1. **Agent side — map the RDP port.** Open the pairing page
   `http://127.0.0.1:8799/?cap=<pairing authorization>` and in
   *3. Local services* press the **Remote Desktop** button. It prefills
   `rdp-001`, protocol `TCP` and target `127.0.0.1:3389`; press *Add service*.
   The page confirms `exposed rdp-001 -> 127.0.0.1:3389`. Restart the Agent
   service from the tray so the supervisor picks the mapping up.
2. **Panel — create the private endpoint.** In the dashboard,
   *Create a private TCP or UDP endpoint*: the paired device,
   `local endpoint id` = `rdp-001` (it must match the Agent mapping exactly,
   character for character), protocol `TCP`, application protocol
   **RDP (TCP only)**. RDP is private by contract: `public` and `both` are
   rejected by the Panel and the Gateway.
3. **Panel — issue a grant and copy the bundle.** On that endpoint's row press
   *Issue Connector grant*. Leave `ttl_minutes` empty for a grant that never
   expires; a whole number of minutes of at least 1 issues exactly that lifetime
   and has no upper bound, which is what to use for a one-time visit. Either
   way the grant carries the contract maximum of concurrent flows (16), so an
   RDP client's companion TCP connection is never refused for capacity. The page shows
   `grant_id`, `token_id`, the
   raw token **once**, and below them the **connect bundle** — one `hx1.…` string
   that carries the gateway, grant, token and protocol together. Only the token's
   SHA-256 digest is stored and published; the bundle is shown once and never
   again. Copy the bundle.
4. **Client — HooshiX Connect.** Start `hooshix-connect.exe`, paste the bundle
   into *Connect bundle*, press **Connect**. The status line becomes
   `listening on 127.0.0.1:13389 (tcp)` and the message line reads
   `tunnel ready — open your client against 127.0.0.1:13389`; **Open Remote
   Desktop** turns on. Press it **once** — it starts `mstsc /v:127.0.0.1:13389`
   as a normal, visible window. **Disconnect** closes the listener, and closing
   the window disconnects first and then exits, so no background process is left
   holding the port.
   The bundle deliberately carries no local listen address, so the app always
   picks `127.0.0.1:13389`; use the CLI below when you want a different port.
   A successful Connect erases the bundle from the edit control — it is a
   one-time credential and the window is often shared or screenshotted — but the
   app keeps it in memory, so **Disconnect → Connect** needs no re-paste. A
   Connect that fails leaves the pasted bundle in place so you can correct it.
   A successful Connect also stores the bundle in `hooshix-connect.cfg`, written
   beside `hooshix-connect.exe`. The next run reads it and opens **without the
   paste area at all**: the window is shorter, and its only bundle control is the
   **Use a different bundle (last saved YYYY-MM-DD)** button, which brings the
   input back when you want to paste a new grant. The file holds the bundle
   protected with the current Windows user's credential (DPAPI), so it is not a
   readable secret and it does not open on another account or machine — copying
   it next to another user's `hooshix-connect.exe` saves nothing. Delete
   `hooshix-connect.cfg` to forget the saved bundle; the paste area returns on
   the next run. A file the app cannot open (a copied or corrupt cfg) never
   hides the input: the window opens normally, says why once after it paints,
   and the next successful Connect overwrites the file.
   The message line follows the tunnel: it appends `— 1 client connected` while
   a client is attached, and `Last client ended: …` after one drops. That is the
   difference between a port nobody dialed and a session that died, which the
   listener state alone cannot show.
   `Status: listening` means the loopback socket is ready — the Gateway checks
   the grant on the first client connection, so a bundle whose grant has been
   revoked (or whose stored expiry has passed) shows up as
   `connector flow ended: … HTTP 401` in the message line when you press
   *Open Remote Desktop*, not at Connect time.
5. **Client — or the command line.** The same bundle works headless; `-bundle`
   replaces `-gateway`, `-grant-id`, `-token-id` and `-token-file`:

   ```powershell
   .\hooshix-connector.exe -bundle hx1.… -listen 127.0.0.1:13389
   mstsc /v:127.0.0.1:13389
   ```

   Passing `-bundle` together with any of those four flags is rejected as a
   contradiction. Without a bundle, `token.txt` must be a regular file no larger
   than 513 bytes containing the raw token, and you delete it when you are done.
   `-ca-file` is the one flag a bundle never replaces: a bundle says where to
   connect, and trusting the Gateway certificate remains the operator's
   decision, so add `-ca-file gateway-ca.pem` only when the Gateway is served by
   a private certificate authority instead of a publicly trusted one.

   Both clients listen on loopback only and open one authenticated WSS flow
   per local TCP connection. Windows presents its own locally generated RDP
   certificate, so the first login shows the expected trust warning; installing
   an enterprise-trusted RDP certificate is a deployment policy task, not part
   of the tunnel.

## One interactive session at a time

HooshiX delivers the login; Windows decides whether it wins a session. On a
**Windows client SKU** (Home, Pro, Pro for Workstations) the licence allows one
interactive session on the machine at a time, console or Remote Desktop, and
`fSingleSessionPerUser=1` additionally allows that account only one session. So
when somebody is signed in at the console of the Agent machine, a remote user who
passes the credential prompt is still refused, and Windows words it as *another
user is already connected* — the message is misleading: it is the **console**
user on that machine, not another remote client.

The target's own event log records it exactly. In
`Microsoft-Windows-TerminalServices-LocalSessionManager` the attempt shows the
arbitration for the new session, its immediate loss, and the console restored:

```
id 41  Begin session arbitration:  User: <account>  Session ID: 3
id 40  Session 3 has been disconnected, reason code 0
id 40  Session 1 has been disconnected, reason code 5
id 25  Session reconnection succeeded: User: <account> Session ID: 1  Source Network Address: LOCAL
id 42  End session arbitration:      User: <account>  Session ID: 3
```

`Source Network Address: LOCAL` on the winner is the tell — the console kept the
single slot. The tunnel did its job: `RemoteConnectionManager` id `1149 User
authentication succeeded` on an earlier attempt from the same bundle proves the
bytes reached `127.0.0.1:3389` and Windows authenticated them.

What to do:

- **Sign the console user out** on the Agent machine (account → *Sign out*).
  Locking or disconnecting does **not** free the slot. Check first with
  `query user`: it must show no active session before the remote client connects.
- Connecting with the *same* account as the console user does not help either —
  arbitration still returns the session to `LOCAL` while the console is logged on.
- **Disconnect every other attached RDP client first.** The same wall has a
  second shape: if the account already has a session that is *connected* to
  another client — typically the operator's own VPN/Tailscale RDP window — the
  listener refuses every other incoming connection, HooshiX included. `query
  session` shows it: the account sits on `rdp-tcp#N` in state `Active` while
  `console` has no user. Only one client can be attached at a time, so the
  second client's reconnect also steals the session back from the first.
- **Open one Remote Desktop window per tunnel, not two.** A third shape of the
  same wall: two `mstsc` windows against the same loopback listener make Windows
  arbitrate the single session back and forth, which looks like a session that
  dies and reconnects every few seconds. `HooshiX Connect` now disables **Open
  Remote Desktop** while a client is attached, precisely so this cannot be
  reached by clicking twice. Count the `261` events of one attempt to tell it
  apart: one `Listener RDP-Tcp received a connection` per attempt is stable, a
  pair about a second apart means two clients are fighting over the session.
- Genuine concurrent remote + local sessions require Windows Server with RDS
  CALs. Do **not** patch `termsrv.dll`: it voids the licence, breaks servicing,
  and HooshiX does not support or troubleshoot patched hosts.

### Telling "the tunnel failed" from "Windows refused"

`Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`
distinguishes the two without any HooshiX tooling. Every connection the tunnel
delivers is logged as id `261 Listener RDP-Tcp received a connection`; a login
Windows then accepts is followed by id `1149 User authentication succeeded`.

| Log shape | Meaning |
| --- | --- |
| `261` then `1149` | the tunnel carried the negotiation and Windows admitted the login |
| `261` with no following `1149` | the bytes reached port 3389 — the failure is Windows refusing the session (single-session arbitration), not the tunnel |
| no `261` at all | the flow never reached the target: check the grant, the Agent mapping, and whether the Connector reported an HTTP error |

To reproduce the middle row without HooshiX in the path, send a bare X.224
Connection Request straight at the listener from the Agent machine itself:

```powershell
$cr = [byte[]]@(3,0,0,19,14,224,0,0,0,0,0,1,0,0,0,0,0,0,0)
$c = New-Object System.Net.Sockets.TcpClient; $c.ReceiveTimeout = 5000
$c.Connect('127.0.0.1', 3389); $s = $c.GetStream(); $s.Write($cr, 0, $cr.Length)
$b = New-Object byte[] 64
try { "reply $($s.Read($b, 0, 64)) bytes" } catch { "refused: $($_.Exception.Message)" }
```

If that probe is refused while a VPN/Tailscale RDP client is attached, the
single-session wall is the cause and the tunnel is innocent — fix the session,
not the Agent.

This page's own scope explains why nothing in the product fixes it: the Agent
never touches `fDenyTSConnections` or session arbitration
(`docs/adr/ADR-0017-private-connector-tcp-and-rdp.md`). Known gap, reported not
fixed: the Panel's *Remote Desktop ready* affordance checks that remote
connections are enabled and the mapping exists — it cannot see whether the single
interactive slot is occupied, so it can read green while Windows refuses the
login.

## Where a flow is recorded

Both ends log every tunnelled flow, so an RDP complaint can be settled without
guessing which side dropped it.

- **Gateway** (`journalctl -u hooshix-gateway`): `connector flow open`, then
  `connector flow closed` with `grant_id`, `endpoint_id`, `device_id`,
  `protocol`, `stream_id` and the flow `duration`. A closed flow logged at
  `Warn` carries the `error` that ended it; a normal hang-up is `Info`.
- **Agent machine** (`C:\ProgramData\HooshiXAgent\agent.log`): `stream open`
  with `endpoint_id` and `target`, then `stream finished` with `outcome`
  (`completed`, `peer_closed`, `local_error`, `send_failed`), `duration`,
  `bytes_sent` and `chunks`. These lines are `Info`, so they reach the file —
  while they were `Debug` the Agent's own log could not answer "did a flow ever
  arrive".
- **Client window**: the message line of `HooshiX Connect`, described in step 4.

Read them in that order. No `connector flow open` on the Gateway means the
Connector was never admitted — check the grant and the bundle. A `stream open`
on the Agent whose next line is `stream dial failed` means the mapping could not
reach its target at all, and one that ends `outcome=local_error` means the flow
reached the machine and `127.0.0.1:3389` refused it: Windows, not the tunnel.
Neither log writes a token; only grant and endpoint IDs appear.

## Test without a second machine

The in-process acceptance test exercises Connector → Gateway → Agent with an
RDP-classified private endpoint and both half-closes:

```bash
go test ./tests/integration -run Private -count=1
```

To probe the wire without an RDP client, point any TCP client at the Connector
listener and check that a Windows X.224 negotiation response comes back — that
proves the full path even if you do not complete a login.

## Disable

- **Revoke one grant:** Panel → *Connector grants* → Revoke. The published
  generation no longer carries it, live flows are cancelled within the bounded
  reauthorization interval, and the next attempt fails closed with the
  Connector reporting `HTTP 401`.
- **Stop the endpoint:** Panel → endpoint row → Disable. Grants for it are
  auto-disabled, and remapping the endpoint cancels active streams.
- **Remove the Agent-side mapping:** pairing page → *3. Local services* →
  Remove, then restart the service from the tray.
- Unpairing the device (`4. Unpair this device`, or `hooshix-agent unpair`)
  drops the session that every flow depends on.
- Grants carry no expiry unless the operator asks for one. Left empty,
  `ttl_minutes` issues a lifetime no deployment will outlive, so revoking is the
  only thing that retires such a grant; a number there issues a grant that does
  end on its stored date. A bundle saved before this change still ends on its
  own stored date either way.
- **The device side has a lifetime of its own.** A device paired before
  2026-10-14 keeps the bounded `expires_at` it was issued with, and nothing
  renews it: the Agent's session token arrives only at a browser-approved
  enrollment claim. Re-pair such a device before that date passes. Re-pairing
  preserves the device key and therefore the same `device_id`, so existing
  endpoint assignments stay valid, and it revokes the previous authorization as
  it always did.

## Failure modes

| Symptom | Cause | Fix |
| --- | --- | --- |
| HooshiX Connect: `connect bundle must start with "hx1."` | pasted the raw token or a truncated copy | copy the whole **Connect bundle** block, not the token |
| HooshiX Connect: `listening` then `connector flow ended: … HTTP 401` on first client connection | the grant was revoked, or one issued with a `ttl_minutes` — or saved before an empty field meant unbounded — has passed its stored `expires_at` | issue a new grant and press *Use a different bundle*; revocation is permanent, so the old bundle never works again |
| HooshiX Connect: `listen on 127.0.0.1:13389: …` | another Connector already holds the port | press Disconnect in the other window, or use the CLI with a different `-listen` |
| Connector exits with `gateway URL must be wss://<host>/connector/v1/connect without credentials, query, or fragment` | wrong `-gateway` scheme, path, query or userinfo | use exactly `wss://edge.hooshix-agent.ir/connector/v1/connect` |
| Connector exits with `x509: certificate signed by unknown authority` | the Gateway is served by a private CA that this machine does not trust | pass `-ca-file gateway-ca.pem` (it combines with `-bundle`), or install the CA into the system store |
| `connector token must be 32..512 non-whitespace characters` | pasted token with a newline or from the wrong grant | re-save the exact token; the token is shown once |
| `token file must be a regular file no larger than 513 bytes` | token piped through a directory, symlink or oversized file | write a fresh small `token.txt` |
| `HTTP 401` at connect time | grant revoked, wrong `grant_id`/`token_id`, endpoint disabled, or a grant issued with a `ttl_minutes` whose `expires_at` has passed | issue a new grant against the enabled endpoint |
| Tray icon turns red with `revoked by gateway` and the supervisor reports `terminal`, so **every** endpoint on that device stops routing | the device's own authorization passed its stored `expires_at`. Authorizations issued before 2026-10-14 are bounded, and nothing renews one: the session token arrives only at a browser-approved enrollment claim | re-pair the device from the pairing page. The new authorization is unbounded, the `device_id` is preserved so endpoint assignments stay valid, and the old authorization is revoked as before |
| `426` / upgrade required | wrong endpoint path or a non-WebSocket client | the Connector owns `/connector/v1/connect`; Agents own `/agent/v1/connect` |
| RDP shows "can't connect" while the Connector is healthy | Windows remote connections off, or the target account lacks RDP permission | enable it in Windows; nothing in HooshiX changes this |
| Connect succeeds but no Remote Desktop window ever appears — no taskbar button, Alt+Tab does not list it, and it flashes into view only after Disconnect | a `hooshix-connect.exe` built before this fix started `mstsc` with `SW_HIDE`, which the client honours for its main window | rebuild or re-download `hooshix-connect.exe`; the window is now created normally |
| HooshiX Connect opens with no *Connect bundle* input at all | an earlier Connect saved `hooshix-connect.cfg` beside the exe, for this Windows account | press **Use a different bundle** to paste another, or delete the cfg to forget the saved one |
| HooshiX Connect says the saved bundle was written for a different Windows account or machine | `hooshix-connect.cfg` was copied from another profile or computer, so DPAPI cannot open it | paste the bundle once more; the next successful Connect rewrites the cfg for this account, and the paste area stays available until then |
| **Open Remote Desktop** is greyed out while the status still says `listening` | a client is already attached to this tunnel, and a second window would steal the machine's one interactive session | work in the window you have; press Disconnect to free the tunnel and start a single new client |
| The session connects, then dies and reconnects every few seconds | two RDP clients competing for one session — the target's event log shows two `261` events about a second apart per attempt | keep exactly one client attached, including VPN/Tailscale windows |
| Login screen appears, credentials pass, then Windows refuses with "another user is already connected" | the Agent machine has a console user signed in and its Windows client SKU allows only one interactive session — arbitration keeps the `LOCAL` session | sign the console user **out** (lock is not enough), verify with `query user`; see *One interactive session at a time* |
| `mstsc` never shows a login prompt: "This computer can't connect to the remote computer", error `0x904` extended `0x7`, while HooshiX Connect still reads `tunnel ready` | the target's listener took the connection (`261`) and refused it before authentication (`1149` missing) because another RDP client is already attached to that account's session | close/disconnect the other RDP client (VPN or Tailscale window), then reconnect through HooshiX; confirm with the `261`/`1149` table in *Telling "the tunnel failed" from "Windows refused"* |
| Flow drops mid-session | TTL expiry, revoke, endpoint remap, service restart, or the per-grant/device/global budgets | re-issue a grant; a lost flow is re-established as a new connection, never resumed |
| TLS failure to the Gateway host | `edge` not published yet on that network, or an expired public certificate | confirm `Resolve-DnsName edge.hooshix-agent.ir` returns the Gateway IP, then let Caddy renew |

There is no insecure fallback: the Connector requires `wss` with certificate
verification, and failed authentication is indistinguishable at the public
boundary so it never discloses whether a grant or endpoint exists.
