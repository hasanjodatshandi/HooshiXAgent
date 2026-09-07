# Technical Specification

## Tunnel Manager

Responsibilities:
- Manage tunnel lifecycle
- Maintain connections
- Detect failures
- Coordinate reconnect

Suggested package:

internal/tunnel/

- manager.go
- connection.go
- health.go
- reconnect.go

## Heartbeat

Messages:
PING
PONG
HEALTH_REPORT

Include:
- timestamp
- latency
- active streams
- version
