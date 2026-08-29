// Package agent implements the AG-5 Edge Agent product runtime.
//
// It owns per-install device identity, local state/secret storage, explicit
// loopback-only endpoint mappings, the outbound WSS/TLS tunnel client,
// reconnect/session/stream behavior, local proxying, and Agent-local UX
// foundations. It does not implement Control Panel server/business logic.
package agent
