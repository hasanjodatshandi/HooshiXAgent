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
		limits.ShutdownTimeout > 0
}
