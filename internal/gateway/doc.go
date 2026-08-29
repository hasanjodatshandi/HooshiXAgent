// Package gateway implements the AG-4 Tunnel Gateway data plane.
//
// It owns only ephemeral authenticated Agent session/stream state, runtime
// routing from validated external metadata, public ingress, bounded traffic
// signals, and the protocol-v1 data-plane enforcement needed by the Gateway.
// It does not implement Control Panel business logic, persistence, or the Edge
// Agent product.
package gateway
