# Agent Runtime Design

Agent lifecycle:

INIT
REGISTERING
CONNECTED
DEGRADED
RECONNECTING
REVOKED
SHUTDOWN

Responsibilities:
- Maintain tunnel
- Report health
- Recover from failures
