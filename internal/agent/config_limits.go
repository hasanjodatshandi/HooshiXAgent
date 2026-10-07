package agent

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// LimitsConfig is the optional "limits" block of the settings file. Every field
// is optional: a field that is absent keeps the compiled-in default, and the
// whole block may be omitted. It exists so an operator can retune the tunnel —
// concurrency, buffer sizes, timeouts and the reconnect backoff — from the
// settings file next to the program instead of rebuilding the Agent.
//
// Durations are written the way Go writes them ("5s", "1m30s"); byte sizes are
// written as a plain number of bytes or with a binary suffix ("2MiB").
type LimitsConfig struct {
	MaxStreams        int    `json:"max_streams,omitempty"`
	MaxQueueFrames    int    `json:"max_queue_frames,omitempty"`
	MaxTunnels        int    `json:"max_tunnels,omitempty"`
	StreamQueueBytes  string `json:"stream_queue_bytes,omitempty"`
	SessionQueueBytes string `json:"session_queue_bytes,omitempty"`
	DialTimeout       string `json:"dial_timeout,omitempty"`
	HandshakeTimeout  string `json:"handshake_timeout,omitempty"`
	WriteTimeout      string `json:"write_timeout,omitempty"`
	IdleTimeout       string `json:"idle_timeout,omitempty"`
	ReconnectMin      string `json:"reconnect_min,omitempty"`
	ReconnectMax      string `json:"reconnect_max,omitempty"`
	// RetryDelay paces the supervisor's own reconnect loop — the pause before
	// the whole tunnel loop is rebuilt after it gave up, as opposed to the
	// per-attempt backoff in reconnect_min/reconnect_max.
	RetryDelay string `json:"retry_delay,omitempty"`
}

// Operator-settable ceilings, deliberately far above any shipped default but
// finite: a mistyped zero, a negative number or a gigabyte-scale buffer must not
// turn the Agent's bounded-resource design (ADR-0005) into unbounded memory or a
// reconnect storm.
const (
	maxConfigStreams       = 256
	maxConfigQueueFrames   = 256
	maxConfigTunnels       = 8
	maxConfigQueueBytes    = 256 << 20
	minConfigTimeout       = time.Second
	maxConfigTimeout       = 15 * time.Minute
	maxConfigReconnectSpan = time.Hour
)

// ApplyLimits returns base with every field the settings file specifies
// overridden. The result — not just the block — is validated, so a combination
// that breaks an invariant shared with the defaults (a session queue below one
// stream queue, a reconnect maximum under the minimum) is refused instead of
// being applied and misbehaving later.
func (config Config) ApplyLimits(base Limits) (Limits, error) {
	if config.Limits == nil {
		return base, nil
	}
	limits := base

	counters := []struct {
		name     string
		value    int
		ceiling  int
		Override *int
	}{
		{"max_streams", config.Limits.MaxStreams, maxConfigStreams, &limits.MaxStreams},
		{"max_queue_frames", config.Limits.MaxQueueFrames, maxConfigQueueFrames, &limits.MaxQueueFrames},
		{"max_tunnels", config.Limits.MaxTunnels, maxConfigTunnels, &limits.MaxTunnels},
	}
	for _, counter := range counters {
		if counter.value == 0 {
			continue
		}
		if counter.value < 1 || counter.value > counter.ceiling {
			return base, fmt.Errorf("limits.%s must be between 1 and %d", counter.name, counter.ceiling)
		}
		*counter.Override = counter.value
	}

	sizes := []struct {
		name     string
		value    string
		Override *int64
	}{
		{"stream_queue_bytes", config.Limits.StreamQueueBytes, &limits.MaxStreamQueueBytes},
		{"session_queue_bytes", config.Limits.SessionQueueBytes, &limits.MaxSessionQueueBytes},
	}
	for _, size := range sizes {
		if strings.TrimSpace(size.value) == "" {
			continue
		}
		bytes, err := parseByteSize(size.value)
		if err != nil {
			return base, fmt.Errorf("limits.%s: %w", size.name, err)
		}
		if bytes > maxConfigQueueBytes {
			return base, fmt.Errorf("limits.%s must not exceed %s", size.name, formatByteSize(maxConfigQueueBytes))
		}
		*size.Override = bytes
	}

	durations := []struct {
		name     string
		value    string
		ceiling  time.Duration
		Override *time.Duration
	}{
		{"dial_timeout", config.Limits.DialTimeout, maxConfigTimeout, &limits.DialTimeout},
		{"handshake_timeout", config.Limits.HandshakeTimeout, maxConfigTimeout, &limits.HandshakeTimeout},
		{"write_timeout", config.Limits.WriteTimeout, maxConfigTimeout, &limits.WriteTimeout},
		{"idle_timeout", config.Limits.IdleTimeout, maxConfigTimeout, &limits.IdleTimeout},
		{"reconnect_min", config.Limits.ReconnectMin, maxConfigReconnectSpan, &limits.ReconnectMin},
		{"reconnect_max", config.Limits.ReconnectMax, maxConfigReconnectSpan, &limits.ReconnectMax},
	}
	for _, entry := range durations {
		if strings.TrimSpace(entry.value) == "" {
			continue
		}
		duration, err := parseConfigDuration(entry.name, entry.value, entry.ceiling)
		if err != nil {
			return base, err
		}
		*entry.Override = duration
	}

	if !limits.valid() {
		return base, fmt.Errorf("limits in the settings file are internally inconsistent: %s", describeLimitsProblem(limits))
	}
	return limits, nil
}

// SupervisorRetryDelay returns the pause the supervisor takes before rebuilding
// the tunnel loop after it gave up. base (the compiled-in default or whatever
// the caller configured) is returned unchanged when the settings file leaves it
// out, so an operator who never wrote retry_delay keeps the shipped pacing.
func (config Config) SupervisorRetryDelay(base time.Duration) (time.Duration, error) {
	if config.Limits == nil || strings.TrimSpace(config.Limits.RetryDelay) == "" {
		return base, nil
	}
	return parseConfigDuration("retry_delay", config.Limits.RetryDelay, maxConfigReconnectSpan)
}

// parseConfigDuration validates one settings-file duration: Go's own duration
// syntax, inside the range that keeps a mistyped value from turning the Agent
// into a busy loop or a machine that never retries.
func parseConfigDuration(name, raw string, ceiling time.Duration) (time.Duration, error) {
	duration, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("limits.%s: %w", name, err)
	}
	if duration < minConfigTimeout || duration > ceiling {
		return 0, fmt.Errorf("limits.%s must be between %s and %s", name, minConfigTimeout, ceiling)
	}
	return duration, nil
}

// describeLimitsProblem names the broken invariant. Limits.valid() is a boolean
// by design, so the operator-facing message enumerates the same clauses instead
// of leaving "invalid Agent limits" in status.json.
func describeLimitsProblem(limits Limits) string {
	switch {
	case limits.MaxStreams < 1, limits.MaxQueueFrames < 1, limits.MaxTunnels < 1:
		return "stream, frame and tunnel counts must all be at least 1"
	case limits.MaxSessionQueueBytes < limits.MaxStreamQueueBytes:
		return "session_queue_bytes must be at least stream_queue_bytes"
	case limits.DialTimeout < minConfigTimeout || limits.HandshakeTimeout < minConfigTimeout ||
		limits.WriteTimeout < minConfigTimeout || limits.IdleTimeout < minConfigTimeout:
		return "every timeout must be at least " + minConfigTimeout.String()
	case limits.ReconnectMax < limits.ReconnectMin:
		return "reconnect_max must be at least reconnect_min"
	default:
		return "the result must satisfy every Agent limit invariant"
	}
}

// parseByteSize accepts a plain byte count or a binary-suffixed size. Only
// binary suffixes are recognised: "KB"/"MB" would introduce a decimal-versus
// binary ambiguity into a file an operator edits by hand.
func parseByteSize(raw string) (int64, error) {
	value := strings.ToUpper(strings.TrimSpace(raw))
	multiplier := int64(1)
	for _, suffix := range []struct {
		name       string
		multiplier int64
	}{
		{"GIB", 1 << 30},
		{"MIB", 1 << 20},
		{"KIB", 1 << 10},
	} {
		if strings.HasSuffix(value, suffix.name) {
			multiplier = suffix.multiplier
			value = strings.TrimSpace(strings.TrimSuffix(value, suffix.name))
			break
		}
	}
	if value == "" {
		return 0, fmt.Errorf("empty byte size %q", raw)
	}
	size, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("byte size %q must be a number of bytes or carry a KiB/MiB/GiB suffix", raw)
	}
	if size < 1 {
		return 0, fmt.Errorf("byte size %q must be at least 1", raw)
	}
	if multiplier > 1 && size > math.MaxInt64/multiplier {
		return 0, fmt.Errorf("byte size %q overflows", raw)
	}
	return size * multiplier, nil
}

func formatByteSize(size int64) string {
	switch {
	case size >= 1<<30 && size%(1<<30) == 0:
		return fmt.Sprintf("%dGiB", size/(1<<30))
	case size >= 1<<20 && size%(1<<20) == 0:
		return fmt.Sprintf("%dMiB", size/(1<<20))
	case size >= 1<<10 && size%(1<<10) == 0:
		return fmt.Sprintf("%dKiB", size/(1<<10))
	default:
		return fmt.Sprintf("%d bytes", size)
	}
}
