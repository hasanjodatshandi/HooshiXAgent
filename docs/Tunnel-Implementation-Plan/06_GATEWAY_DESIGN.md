# Gateway Design

Gateway responsibilities:

- Accept authenticated agents
- Maintain sessions
- Route streams
- Apply limits
- Expose metrics

Recommended modules:

internal/gateway/
- session_registry
- tunnel_manager
- router
- health
- metrics
