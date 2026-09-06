# Target Architecture

```
Cloud Application
       |
HTTP/API Layer
       |
Tunnel Gateway
       |
Tunnel Session Manager
       |
Secure WSS/TLS Tunnel
       |
HooshiX Edge Agent
       |
Local Services
```

Design principles:
- Agent initiates outbound connections only.
- Gateway never directly connects to private networks.
- Control Plane remains external.
