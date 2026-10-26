# HooshiX Agent setup UI

React + TypeScript SPA for the loopback-only Agent setup page. The compiled
bundle is embedded into the Agent binary by `internal/agent/webapp/ui.go`.

## Build

Use Node 24 (the version CI pins). From this directory:

```sh
npm ci
npm run build
```

`dist/` is committed on purpose: `go build` must produce a working UI from a
clean checkout with no Node toolchain. CI rebuilds the bundle and fails on any
drift, so run `npm run build` and commit `dist/` whenever source changes.

The production flow is build → `go build`/`go run` of the Agent → open the
pairing page from the tray. There is no Vite dev proxy because the API is
capability-gated and only exists on the service's loopback listener.

## Delivery and security contract

- `GET /` serves the shell only to a caller holding the pairing capability;
  everyone else gets the capability-free bootstrap page.
- `GET /api/state` (capability via `?cap=` or `X-HooshiX-Pairing-Capability`)
  carries the rendering state and the per-process CSRF token. It never carries
  the session token, the private key or the capability.
- `/boot.js`, `/favicon.svg` and hashed `/assets/*` are public: they contain no
  state or secret. Hashed assets are immutable; root files are `no-cache`.
- Mutations keep the existing gates: local-origin check, capability, CSRF
  (`X-HooshiX-CSRF`), and `application/json` for enrollment.
- A successful enrollment or explicit rotate changes the capability; the UI
  adopts the value returned by the API (`replaceCapability`) before refreshing.
- `HashRouter` keeps `?cap=` in front of the hash so deep links remain
  authenticated.
- The CSP forbids inline/remote script (`default-src 'none'; script-src
  'self'`), framing, and non-self connections.

UI source lives in `src/`; the bilingual dictionaries and status mapping are in
`src/lib/`. Keep every user-visible string in both `fa` and `en`.
