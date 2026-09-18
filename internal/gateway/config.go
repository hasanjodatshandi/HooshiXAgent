package gateway

import "time"

type Limits struct {
	MaxAgentSessions        int
	MaxPendingHandshakes    int
	MaxStreamsPerSession    int
	MaxStreamQueueFrames    int
	MaxStreamQueueBytes     int64
	MaxSessionQueueBytes    int64
	MaxGlobalQueueBytes     int64
	MaxIngressInFlight      int
	MaxIngressInFlightBytes int64
	HandshakeRatePerSecond  int
	HandshakeRateBurst      int
	IngressRatePerSecond    int
	IngressRateBurst        int
	MaxRequestBytes         int64
	MaxResponseBytes        int64
	MaxHeaderBytes          int
	MaxStatusQueueSignals   int
	StatusEmitTimeout       time.Duration
	HandshakeTimeout        time.Duration
	ReadTimeout             time.Duration
	WriteTimeout            time.Duration
	HeartbeatInterval       time.Duration
	IdleTimeout             time.Duration
	ShutdownTimeout         time.Duration
	// MaxTunnelsPerDevice bounds the Phase-3 HA concurrent tunnels one
	// device may hold on this gateway (primary plus standby tunnels).
	MaxTunnelsPerDevice int
	// ResponsePhaseTimeout bounds the tunneled-response phase (tunneled
	// response headers plus the streamed body) by inactivity: every chunk
	// forwarded in either direction re-arms it. It is an idle bound, not a
	// total-duration bound, so it cannot impose a throughput floor on a
	// progressing transfer while still bounding an Agent that keeps
	// answering heartbeats but never finishes a response. Defaults to
	// IdleTimeout.
	ResponsePhaseTimeout time.Duration
	// ResumeAcceptanceWindow bounds how old a resume_session proof may be,
	// measured against the Gateway clock. A captured resume frame is
	// therefore replayable for at most this long (the Gateway-issued resume
	// challenge is additionally rotated on every accepted resume).
	ResumeAcceptanceWindow time.Duration
	// PreAuthRatePerSecond/PreAuthRateBurst bound pre-authentication Agent
	// connections per trusted peer before a pending-handshake slot is taken.
	// They are deliberately separate from the authenticated handshake bucket
	// so unauthenticated traffic never spends authenticated-handshake rate.
	PreAuthRatePerSecond int
	PreAuthRateBurst     int
	// TrustedProxyPeers lists the IPs/CIDRs (for example "127.0.0.1/32",
	// "172.16.0.0/12") of the public edge that terminates client TLS in front
	// of this Gateway. Only when the immediate request peer is inside this set
	// is the edge-supplied X-Forwarded-For hop treated as the client address;
	// otherwise the immediate peer address is used and any client-supplied
	// forwarding header is discarded. This is a trust setting, not a resource
	// limit; an empty list trusts no proxy at all.
	TrustedProxyPeers []string
}

func DefaultLimits() Limits {
	return Limits{
		MaxAgentSessions:        64,
		MaxPendingHandshakes:    64,
		MaxStreamsPerSession:    64,
		MaxStreamQueueFrames:    16,
		MaxStreamQueueBytes:     2 << 20,
		MaxSessionQueueBytes:    8 << 20,
		MaxGlobalQueueBytes:     32 << 20,
		MaxIngressInFlight:      32,
		MaxIngressInFlightBytes: 32 << 20,
		HandshakeRatePerSecond:  32,
		HandshakeRateBurst:      64,
		IngressRatePerSecond:    256,
		IngressRateBurst:        512,
		MaxRequestBytes:         8 << 20,
		MaxResponseBytes:        32 << 20,
		MaxHeaderBytes:          32 << 10,
		MaxStatusQueueSignals:   256,
		StatusEmitTimeout:       2 * time.Second,
		HandshakeTimeout:        10 * time.Second,
		ReadTimeout:             15 * time.Second,
		WriteTimeout:            10 * time.Second,
		HeartbeatInterval:       15 * time.Second,
		IdleTimeout:             45 * time.Second,
		ShutdownTimeout:         10 * time.Second,
		MaxTunnelsPerDevice:     2,
		// The response phase is bounded by the same inactivity budget the
		// protocol already uses for a stalled session, so no throughput floor
		// is added to any progressing transfer.
		ResponsePhaseTimeout:   45 * time.Second,
		ResumeAcceptanceWindow: time.Minute,
		// Pre-authentication throttling is deliberately permissive enough for
		// one peer's legitimate reconnect storms (a misconfigured edge reaches
		// the Gateway as a single peer key, so every device behind it shares
		// this bucket) while still bounding slot cycling.
		PreAuthRatePerSecond: 16,
		PreAuthRateBurst:     32,
	}
}

func (limits Limits) valid() bool {
	return limits.MaxAgentSessions > 0 &&
		limits.MaxPendingHandshakes > 0 &&
		limits.MaxStreamsPerSession > 0 &&
		limits.MaxStreamQueueFrames > 0 &&
		limits.MaxStreamQueueBytes > 0 &&
		limits.MaxSessionQueueBytes >= limits.MaxStreamQueueBytes &&
		limits.MaxGlobalQueueBytes >= limits.MaxSessionQueueBytes &&
		limits.MaxIngressInFlight > 0 &&
		limits.MaxIngressInFlightBytes > 0 &&
		limits.HandshakeRatePerSecond > 0 && limits.HandshakeRateBurst > 0 &&
		limits.IngressRatePerSecond > 0 && limits.IngressRateBurst > 0 &&
		limits.MaxRequestBytes > 0 &&
		limits.MaxResponseBytes > 0 &&
		limits.MaxHeaderBytes > 0 &&
		limits.MaxStatusQueueSignals > 0 && limits.StatusEmitTimeout > 0 &&
		limits.MaxIngressInFlightBytes >= limits.MaxRequestBytes+int64(limits.MaxHeaderBytes) &&
		limits.HandshakeTimeout > 0 &&
		limits.ReadTimeout > 0 &&
		limits.WriteTimeout > 0 &&
		limits.HeartbeatInterval >= 5*time.Second && limits.HeartbeatInterval <= 60*time.Second &&
		limits.IdleTimeout >= 15*time.Second && limits.IdleTimeout <= 300*time.Second &&
		limits.IdleTimeout >= 2*limits.HeartbeatInterval &&
		limits.ShutdownTimeout > 0 &&
		limits.MaxTunnelsPerDevice > 0 &&
		limits.ResponsePhaseTimeout > 0 &&
		limits.ResumeAcceptanceWindow > 0 &&
		limits.PreAuthRatePerSecond > 0 && limits.PreAuthRateBurst > 0
}
