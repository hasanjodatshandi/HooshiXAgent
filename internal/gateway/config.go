package gateway

import "time"

type Limits struct {
	MaxAgentSessions     int
	MaxPendingHandshakes int
	MaxStreamsPerSession int
	MaxStreamQueueFrames int
	MaxRequestBytes      int64
	MaxResponseBytes     int64
	MaxHeaderBytes       int
	HandshakeTimeout     time.Duration
	ReadTimeout          time.Duration
	WriteTimeout         time.Duration
	HeartbeatInterval    time.Duration
	IdleTimeout          time.Duration
	ShutdownTimeout      time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		MaxAgentSessions:     1024,
		MaxPendingHandshakes: 128,
		MaxStreamsPerSession: 64,
		MaxStreamQueueFrames: 16,
		MaxRequestBytes:      8 << 20,
		MaxResponseBytes:     32 << 20,
		MaxHeaderBytes:       32 << 10,
		HandshakeTimeout:     10 * time.Second,
		ReadTimeout:          15 * time.Second,
		WriteTimeout:         10 * time.Second,
		HeartbeatInterval:    15 * time.Second,
		IdleTimeout:          45 * time.Second,
		ShutdownTimeout:      10 * time.Second,
	}
}

func (limits Limits) valid() bool {
	return limits.MaxAgentSessions > 0 &&
		limits.MaxPendingHandshakes > 0 &&
		limits.MaxStreamsPerSession > 0 &&
		limits.MaxStreamQueueFrames > 0 &&
		limits.MaxRequestBytes > 0 &&
		limits.MaxResponseBytes > 0 &&
		limits.MaxHeaderBytes > 0 &&
		limits.HandshakeTimeout > 0 &&
		limits.ReadTimeout > 0 &&
		limits.WriteTimeout > 0 &&
		limits.HeartbeatInterval >= 5*time.Second && limits.HeartbeatInterval <= 60*time.Second &&
		limits.IdleTimeout >= 15*time.Second && limits.IdleTimeout <= 300*time.Second &&
		limits.IdleTimeout >= 2*limits.HeartbeatInterval &&
		limits.ShutdownTimeout > 0
}
