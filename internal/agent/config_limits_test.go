package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAbsentLimitsBlockKeepsEveryCompiledDefault(t *testing.T) {
	base := DefaultLimits()
	limits, err := Config{Version: configVersion}.ApplyLimits(base)
	if err != nil {
		t.Fatal(err)
	}
	if limits != base {
		t.Fatalf("an absent limits block changed the defaults: %+v", limits)
	}
	if base != DefaultLimits() {
		t.Fatal("ApplyLimits mutated the caller's base limits")
	}
}

func TestLimitsBlockOverridesOnlyWhatTheOperatorWrote(t *testing.T) {
	base := DefaultLimits()
	config := Config{Version: configVersion, Limits: &LimitsConfig{
		MaxStreams:        128,
		SessionQueueBytes: "16MiB",
		IdleTimeout:       "2m30s",
		ReconnectMax:      "45s",
	}}
	limits, err := config.ApplyLimits(base)
	if err != nil {
		t.Fatal(err)
	}
	if limits.MaxStreams != 128 {
		t.Errorf("MaxStreams = %d, want 128", limits.MaxStreams)
	}
	if limits.MaxSessionQueueBytes != 16<<20 {
		t.Errorf("MaxSessionQueueBytes = %d, want %d", limits.MaxSessionQueueBytes, int64(16<<20))
	}
	if limits.IdleTimeout != 150*time.Second {
		t.Errorf("IdleTimeout = %s, want 2m30s", limits.IdleTimeout)
	}
	if limits.ReconnectMax != 45*time.Second {
		t.Errorf("ReconnectMax = %s, want 45s", limits.ReconnectMax)
	}
	// Untouched fields must stay at the compiled-in values, not zero out.
	if limits.MaxQueueFrames != base.MaxQueueFrames || limits.MaxTunnels != base.MaxTunnels ||
		limits.MaxStreamQueueBytes != base.MaxStreamQueueBytes || limits.DialTimeout != base.DialTimeout ||
		limits.HandshakeTimeout != base.HandshakeTimeout || limits.WriteTimeout != base.WriteTimeout ||
		limits.ReconnectMin != base.ReconnectMin {
		t.Fatalf("unspecified fields changed: %+v", limits)
	}
}

func TestLimitsBlockRefusesValuesOutsideTheSafeRange(t *testing.T) {
	cases := []struct {
		name    string
		limits  LimitsConfig
		failure string
	}{
		{"streams above the ceiling", LimitsConfig{MaxStreams: maxConfigStreams + 1}, "limits.max_streams"},
		{"negative stream count", LimitsConfig{MaxStreams: -1}, "limits.max_streams"},
		{"queue frames above the ceiling", LimitsConfig{MaxQueueFrames: maxConfigQueueFrames + 1}, "limits.max_queue_frames"},
		{"tunnels above the ceiling", LimitsConfig{MaxTunnels: maxConfigTunnels + 1}, "limits.max_tunnels"},
		{"decimal byte suffix", LimitsConfig{StreamQueueBytes: "2MB"}, "limits.stream_queue_bytes"},
		{"non-numeric byte size", LimitsConfig{StreamQueueBytes: "large"}, "limits.stream_queue_bytes"},
		{"zero byte size", LimitsConfig{SessionQueueBytes: "0"}, "limits.session_queue_bytes"},
		{"byte size above the ceiling", LimitsConfig{SessionQueueBytes: "1GiB"}, "limits.session_queue_bytes"},
		{"timeout below the floor", LimitsConfig{DialTimeout: "500ms"}, "limits.dial_timeout"},
		{"timeout above the ceiling", LimitsConfig{IdleTimeout: "20m"}, "limits.idle_timeout"},
		{"unparsable duration", LimitsConfig{IdleTimeout: "ten seconds"}, "limits.idle_timeout"},
		{"reconnect above the ceiling", LimitsConfig{ReconnectMax: "2h"}, "limits.reconnect_max"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			block := testCase.limits
			_, err := Config{Version: configVersion, Limits: &block}.ApplyLimits(DefaultLimits())
			if err == nil {
				t.Fatalf("accepted %+v", block)
			}
			if !strings.Contains(err.Error(), testCase.failure) {
				t.Fatalf("error %q does not name %q", err, testCase.failure)
			}
		})
	}
}

func TestLimitsBlockCannotBreakAnInvariantSharedWithTheDefaults(t *testing.T) {
	cases := []struct {
		name    string
		limits  LimitsConfig
		failure string
	}{
		{
			"session queue below one stream queue",
			LimitsConfig{SessionQueueBytes: "1MiB"},
			"session_queue_bytes must be at least stream_queue_bytes",
		},
		{
			"reconnect maximum under the minimum",
			LimitsConfig{ReconnectMin: "10s", ReconnectMax: "5s"},
			"reconnect_max must be at least reconnect_min",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			block := testCase.limits
			limits, err := Config{Version: configVersion, Limits: &block}.ApplyLimits(DefaultLimits())
			if err == nil {
				t.Fatalf("accepted an inconsistent result: %+v", limits)
			}
			if !strings.Contains(err.Error(), testCase.failure) {
				t.Fatalf("error %q does not explain %q", err, testCase.failure)
			}
			if !strings.Contains(err.Error(), "settings file") {
				t.Fatalf("error %q does not tell the operator where the mistake lives", err)
			}
			if limits != DefaultLimits() {
				t.Fatalf("a rejected block still changed the limits: %+v", limits)
			}
		})
	}
}

// TestLimitsBlockTravelsThroughTheSettingsFile is the operator-facing contract:
// the block is hand-edited JSON, so the strict decoder must accept it, saving
// must not drop it, and the limits must arrive on the other side of the reload.
func TestLimitsBlockTravelsThroughTheSettingsFile(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, settingsFileName),
		[]byte(`{"version":1,"update_channel":"stable","limits":{"max_streams":96,"stream_queue_bytes":"4MiB","idle_timeout":"90s","reconnect_max":"1m"}}`+"\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if config.Limits == nil {
		t.Fatal("the limits block did not survive decoding")
	}
	limits, err := config.ApplyLimits(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if limits.MaxStreams != 96 || limits.MaxStreamQueueBytes != 4<<20 ||
		limits.IdleTimeout != 90*time.Second || limits.ReconnectMax != time.Minute {
		t.Fatalf("limits from the settings file were not applied: %+v", limits)
	}

	if err := SaveConfig(stateDir, config); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadConfig(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Limits == nil || reloaded.Limits.MaxStreams != 96 || reloaded.Limits.ReconnectMax != "1m" {
		t.Fatalf("saving dropped the limits block: %+v", reloaded.Limits)
	}
}

func TestSupervisorRetryDelayFollowsTheSettingsFile(t *testing.T) {
	const base = 5 * time.Second
	cases := []struct {
		name    string
		limits  *LimitsConfig
		want    time.Duration
		failure string
	}{
		{"absent block keeps the shipped pacing", nil, base, ""},
		{"absent field keeps the shipped pacing", &LimitsConfig{MaxStreams: 8}, base, ""},
		{"set by the operator", &LimitsConfig{RetryDelay: " 45s "}, 45 * time.Second, ""},
		{"maximum", &LimitsConfig{RetryDelay: "1h"}, time.Hour, ""},
		{"below the floor", &LimitsConfig{RetryDelay: "250ms"}, 0, "limits.retry_delay"},
		{"above the ceiling", &LimitsConfig{RetryDelay: "90m"}, 0, "limits.retry_delay"},
		{"not a duration", &LimitsConfig{RetryDelay: "soon"}, 0, "limits.retry_delay"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			config := Config{Version: configVersion, Limits: testCase.limits}
			got, err := config.SupervisorRetryDelay(base)
			if testCase.failure != "" {
				if err == nil || !strings.Contains(err.Error(), testCase.failure) {
					t.Fatalf("error = %v, want one naming %q", err, testCase.failure)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != testCase.want {
				t.Fatalf("retry delay = %s, want %s", got, testCase.want)
			}
		})
	}
}

func TestParseByteSizeAcceptsTheDocumentedForms(t *testing.T) {
	cases := []struct {
		raw  string
		want int64
	}{
		{"2097152", 2 << 20},
		{"2MiB", 2 << 20},
		{" 2 mib ", 2 << 20},
		{"512KiB", 512 << 10},
		{"1GiB", 1 << 30},
	}
	for _, testCase := range cases {
		got, err := parseByteSize(testCase.raw)
		if err != nil {
			t.Fatalf("parseByteSize(%q): %v", testCase.raw, err)
		}
		if got != testCase.want {
			t.Fatalf("parseByteSize(%q) = %d, want %d", testCase.raw, got, testCase.want)
		}
	}
	for _, raw := range []string{"", "   ", "MiB", "2 MB", "-1", "1.5MiB", "99999999999999999999999"} {
		if _, err := parseByteSize(raw); err == nil {
			t.Fatalf("parseByteSize accepted %q", raw)
		}
	}
}

func TestFormatByteSizeRoundTripsTheCeilings(t *testing.T) {
	for _, size := range []int64{1 << 10, 2 << 20, maxConfigQueueBytes} {
		text := formatByteSize(size)
		parsed, err := parseByteSize(text)
		if err != nil {
			t.Fatalf("formatByteSize(%d) = %q which does not parse back: %v", size, text, err)
		}
		if parsed != size {
			t.Fatalf("formatByteSize(%d) = %q, parsed back as %d", size, text, parsed)
		}
	}
}
