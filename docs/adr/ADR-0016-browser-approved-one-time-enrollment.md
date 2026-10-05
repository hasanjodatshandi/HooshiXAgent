# ADR-0016: Browser-approved one-time device enrollment

Status: Accepted  
Date: 2026-09-27

## Context

Setup must register a device with a user account without collecting the account
password or exporting the Agent private key. A pasted long-lived token is not an
acceptable installation experience and makes replay and secret handling hard to
reason about.

## Decision

Use the device-code exchange documented by the Panel in
`docs/enrollment-protocol-v1.md`. The Agent service creates/owns the Ed25519 key,
requests a ten-minute enrollment and proves possession by signing a
domain-separated challenge. Setup talks only to the identity-verified,
capability/CSRF-protected loopback service, displays the human code and opens the
Panel approval page. A logged-in browser approves the request. The service
claims the credential with a separate high-entropy poll token.

The Panel stores hashes of the human and poll secrets. Device creation,
authorization issue and request consumption are one transaction. The raw token
is returned once and is then protected through the existing Agent local-secret
boundary. Lost responses require a new enrollment; the server does not retain a
replayable plaintext credential.

## Consequences

- Setup never handles the account password.
- Browser authentication and CSRF remain separate from Agent authentication.
- Possession of a human code alone cannot register an attacker-controlled key;
  approval is blocked until the submitted public key proves possession.
- A user may repeat the same flow for multiple Devices under one account.
- Enrollment requires HTTPS in production and an independently rate-limited
  public API.

## Verification

Automated Panel/Agent tests cover forged proof, missing proof, wrong poll
secret, expiry, second-owner approval, replay, CSRF-protected approval, two
Devices for one account, same-key repair and service-owned state commit. The
elevated packaged-Setup/two-PC runtime gate remains open in phase 2.
