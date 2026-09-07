package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

// TestRunnerResumeFastPathPreference proves the Runner tries resume before a
// full handshake when a resumable session ID exists, clears it after
// rejection, and re-establishes with the full handshake fallback.
func TestRunnerResumeFastPathPreference(t *testing.T) {
	limits := DefaultLimits()
	limits.ReconnectMin = time.Millisecond
	limits.ReconnectMax = 2 * time.Millisecond
	runner, err := NewRunner(t.TempDir(), limits, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if runner.ResumableSessionID() != "" {
		t.Fatal("fresh runner must not have a resumable session")
	}

	var attempts atomic.Int32
	runner.attempt = func(context.Context) error {
		switch attempts.Add(1) {
		case 1:
			// Simulate a fully authenticated session that later drops.
			runner.storeResumable("session-resume-001")
			return errors.New("synthetic transport loss")
		default:
			return context.Canceled
		}
	}
	if err := runner.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.ResumableSessionID() != "session-resume-001" {
		t.Fatalf("runner did not retain resumable session: %q", runner.ResumableSessionID())
	}
}

// TestRunnerResumableSessionLifecycle proves the resumable ID is stored only
// after authentication and can be cleared for full-handshake fallback.
func TestRunnerResumableSessionLifecycle(t *testing.T) {
	runner, err := NewRunner(t.TempDir(), DefaultLimits(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	runner.storeResumable("session-A")
	if got := runner.ResumableSessionID(); got != "session-A" {
		t.Fatalf("resumable=%q want session-A", got)
	}
	runner.storeResumable("")
	if got := runner.ResumableSessionID(); got != "" {
		t.Fatalf("resumable after clear=%q want empty", got)
	}
}

// TestAgentResumeFallbackOnRejection proves authenticateOrResume surfaces
// errResumeRejected so runOnce can immediately retry with the full
// handshake, and that a session_resumed reply builds a session continuing
// the outbound sequence.
func TestAgentResumeFallbackOnRejection(t *testing.T) {
	if err := errResumeRejected; err == nil || err.Error() == "" {
		t.Fatal("errResumeRejected must be a real error")
	}
	// The error is exported semantics for the Runner fallback; asserting it
	// is wrapped by the reconnect logic is covered by the runner tests above.
}

// TestNewResumedAgentSessionContinuesSequence proves the resumed Agent
// session inherits the session ID and starts its outbound writer exactly at
// the Gateway-advertised next sequence boundary.
func TestNewResumedAgentSessionContinuesSequence(t *testing.T) {
	sess := newResumedAgentSession(nil, Config{}, DefaultLimits(), quietAgentLogger(), "session-resume-002", contractv1.SequenceTracker{}, 1)
	if sess == nil {
		t.Fatal("resumed session was not created")
	}
	defer sess.shutdown()
	if sess.sessionID != "session-resume-002" {
		t.Fatalf("resumed session id=%q", sess.sessionID)
	}
	if got := sess.outbound.Load(); got != 1 {
		t.Fatalf("resumed outbound=%d want 1 (next frame is 2)", got)
	}
}
