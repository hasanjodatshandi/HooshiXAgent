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
3. **Panel — issue a grant and copy the bundle.** On that endpoint's row, set
   `ttl_minutes` (1–60) and `max_connections` (the form defaults to 4 for RDP;
   do not set it to 1 — an RDP client commonly opens a companion TCP connection
   while it negotiates, and the Connector opens one grant slot per local
   connection, so a single-connection grant answers the second one with
   `HTTP 503 connector capacity reached`)
   and press *Issue Connector grant*. The page shows `grant_id`, `token_id`, the
   raw token **once**, and below them the **connect bundle** — one `hx1.…` string
   that carries the gateway, grant, token and protocol together. Only the token's
   SHA-256 digest is stored and published; the bundle is shown once and never
   again. Copy the bundle.
4. **Client — HooshiX Connect.** Start `hooshix-connect.exe`, paste the bundle
   into *Connect bundle*, press **Connect**. The status line becomes
   `listening on 127.0.0.1:13389 (tcp)` and **Open Remote Desktop** turns on;
   press it to start `mstsc /v:127.0.0.1:13389`. **Disconnect** closes the
   listener, and closing the window disconnects first and then exits, so no
   background process is left holding the port.
   The bundle deliberately carries no local listen address, so the app always
   picks `127.0.0.1:13389`; use the CLI below when you want a different port.
   `Status: listening` means the loopback socket is ready — the Gateway checks
   the grant on the first client connection, so an expired or revoked bundle
   shows up as `connector flow ended: … HTTP 401` in the message line when you
   press *Open Remote Desktop*, not at Connect time.
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
- Letting the TTL expire ends the grant by itself; grants are short-lived on
  purpose.

## Failure modes

| Symptom | Cause | Fix |
| --- | --- | --- |
| HooshiX Connect: `connect bundle must start with "hx1."` | pasted the raw token or a truncated copy | copy the whole **Connect bundle** block, not the token |
| HooshiX Connect: `listening` then `connector flow ended: … HTTP 401` on first client connection | grant expired or revoked between Connect and use | issue a new grant; the bundle's lifetime is the grant's lifetime |
| HooshiX Connect: `listen on 127.0.0.1:13389: …` | another Connector already holds the port | press Disconnect in the other window, or use the CLI with a different `-listen` |
| Connector exits with `gateway URL must be wss://<host>/connector/v1/connect without credentials, query, or fragment` | wrong `-gateway` scheme, path, query or userinfo | use exactly `wss://edge.hooshix-agent.ir/connector/v1/connect` |
| Connector exits with `x509: certificate signed by unknown authority` | the Gateway is served by a private CA that this machine does not trust | pass `-ca-file gateway-ca.pem` (it combines with `-bundle`), or install the CA into the system store |
| `connector token must be 32..512 non-whitespace characters` | pasted token with a newline or from the wrong grant | re-save the exact token; the token is shown once |
| `token file must be a regular file no larger than 513 bytes` | token piped through a directory, symlink or oversized file | write a fresh small `token.txt` |
| `HTTP 401` at connect time | grant revoked, expired, wrong `grant_id`/`token_id`, or endpoint disabled | issue a new grant against the enabled endpoint |
| `426` / upgrade required | wrong endpoint path or a non-WebSocket client | the Connector owns `/connector/v1/connect`; Agents own `/agent/v1/connect` |
| RDP shows "can't connect" while the Connector is healthy | Windows remote connections off, or the target account lacks RDP permission | enable it in Windows; nothing in HooshiX changes this |
| Login screen appears, credentials pass, then Windows refuses with "another user is already connected" | the Agent machine has a console user signed in and its Windows client SKU allows only one interactive session — arbitration keeps the `LOCAL` session | sign the console user **out** (lock is not enough), verify with `query user`; see *One interactive session at a time* |
| `mstsc` never shows a login prompt: "This computer can't connect to the remote computer", error `0x904` extended `0x7`, while HooshiX Connect still reads `tunnel ready` | the target's listener took the connection (`261`) and refused it before authentication (`1149` missing) because another RDP client is already attached to that account's session | close/disconnect the other RDP client (VPN or Tailscale window), then reconnect through HooshiX; confirm with the `261`/`1149` table in *Telling "the tunnel failed" from "Windows refused"* |
| Flow drops mid-session | TTL expiry, revoke, endpoint remap, service restart, or the per-grant/device/global budgets | re-issue a grant; a lost flow is re-established as a new connection, never resumed |
| TLS failure to the Gateway host | `edge` not published yet on that network, or an expired public certificate | confirm `Resolve-DnsName edge.hooshix-agent.ir` returns the Gateway IP, then let Caddy renew |

There is no insecure fallback: the Connector requires `wss` with certificate
verification, and failed authentication is indistinguishable at the public
boundary so it never discloses whether a grant or endpoint exists.
