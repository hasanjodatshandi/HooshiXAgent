# HooshiXAgent Security Standard

**Status:** Normative

HooshiXAgent exposes explicitly approved local services to hostile public traffic. Security failures are release-blocking and leaf-blocking when the affected security gate is applicable.

## 1. Untrusted input validation

For every untrusted input, implementation MUST define:

- source;
- type;
- canonicalization;
- allowlist;
- length/range;
- semantic constraints;
- authorization context;
- rejection behavior.

Use allowlist-first validation.

Generic "sanitization" is not a substitute for parsing, validation, authorization, and context-specific encoding.

## 2. Local-target / SSRF policy

Default MVP local targets are limited to:

```text
127.0.0.0/8
::1
localhost
```

Denied by default unless a later explicitly approved feature/ADR changes policy:

- arbitrary LAN addresses;
- link-local ranges;
- cloud metadata endpoints;
- multicast or broadcast targets;
- `file:` URLs;
- arbitrary schemes;
- named pipes;
- Unix sockets.

Public callers MUST NOT select a raw local target.

The Gateway MUST NOT instruct the Agent to dial an arbitrary address. Gateway routing references a locally approved endpoint mapping.

## 3. Device identity and enrollment material

Each install creates a unique Ed25519 identity.

Rules:

- never ship one shared private key;
- the device private key never leaves the device;
- enrollment/authorization tokens are short-lived;
- enrollment/authorization tokens are one-time where specified by the external contract;
- tokens are scoped;
- replay resistance is mandatory.

The separate HooshiX Control Panel remains external. This repository consumes only the approved external authorization/session/endpoint contract and does not implement Control Panel account or enrollment-management business logic.

## 4. Agent transport protocol safety

Production Agent transport is:

```text
WSS/TLS on TCP 443
```

The protocol MUST enforce:

- TLS certificate verification;
- authenticated handshake;
- protocol version negotiation;
- replay protection;
- maximum frame size;
- maximum streams;
- bounded queues;
- heartbeat;
- read timeout;
- write timeout;
- idle timeout;
- malformed-frame rejection;
- no insecure production fallback.

TLS verification may not be disabled in production.

## 5. Resource and DoS safety

Applicable runtime limits MUST bound:

- public request bodies and headers;
- Agent connections;
- streams per device/session;
- requests per endpoint where applicable;
- queues/channels;
- pools;
- retries;
- connection/authentication/handshake rates;
- telemetry/log output.

Unbounded resource growth is a security and reliability failure.

## 6. Authentication / authorization boundary

Authentication and authorization decisions must use explicit validated inputs and the approved trust boundary.

Telemetry, logs, health state, or convenience caches MUST NOT become authentication, authorization, or business authority.

Externally supplied Control Panel metadata is untrusted at the transport boundary until validated according to the approved integration contract and applicable authorization context.

## 7. Secrets and sensitive data

Do not log or persist in evidence:

- passwords;
- enrollment codes;
- auth/session tokens;
- private keys;
- datastore credentials;
- full sensitive payloads.

Security evidence should prove behavior without exposing secrets or PII.

## 8. Security testing

Applicable security tests include:

- invalid and boundary input tests;
- SSRF/local-target rejection tests;
- auth failure and replay tests;
- malformed and oversized frame tests;
- connection/stream/resource exhaustion tests;
- insecure TLS/fallback rejection tests;
- secret-canary/logging checks;
- dependency vulnerability scanning;
- source/history secret scanning;
- high-signal static security rules.

A known applicable security failure blocks completion. Do not disable, downgrade, suppress broadly, or convert a blocking security gate into a warning to obtain a passing result.
