// Package tunnelwindow implements the sender-side credit accounting for one
// ADR-0021 tunnel stream. It is pure concurrency state: the receiver grants
// credit with stream_window_update frames, the sender takes credit before each
// data frame, and closing the stream wakes every waiter.
package tunnelwindow

import (
	"context"
	"errors"
	"sync"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

var (
	ErrClosed    = errors.New("stream window closed")
	ErrInvalid   = errors.New("stream window credit outside bounds")
	ErrOverGrant = errors.New("stream window credit exceeds the unacked limit")
)

// Window starts at zero credit: the receiver's first stream_window_update
// carries the initial window, so a sender never assumes more buffer than the
// receiver actually configured.
type Window struct {
	mu     sync.Mutex
	credit int64
	limit  int64
	closed bool
	err    error
	// changed is closed and replaced on every state change, broadcasting to
	// every blocked Take.
	changed chan struct{}
}

func New(limit int64) *Window {
	if limit <= 0 {
		limit = 1
	}
	return &Window{limit: limit, changed: make(chan struct{})}
}

func (window *Window) Credit() int64 {
	window.mu.Lock()
	defer window.mu.Unlock()
	return window.credit
}

// Take blocks until at least size credit is available, then consumes it.
func (window *Window) Take(ctx context.Context, size int64) error {
	if size <= 0 || size > window.limit {
		return ErrInvalid
	}
	for {
		window.mu.Lock()
		if window.closed {
			err := window.err
			window.mu.Unlock()
			if err == nil {
				err = ErrClosed
			}
			return err
		}
		if window.credit >= size {
			window.credit -= size
			window.mu.Unlock()
			return nil
		}
		changed := window.changed
		window.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Add applies a receiver grant. The outstanding unused credit may never exceed
// the configured limit; an over-grant is a protocol violation, not a larger
// buffer.
func (window *Window) Add(size int64) error {
	if size <= 0 || size > window.limit {
		return ErrInvalid
	}
	window.mu.Lock()
	defer window.mu.Unlock()
	if window.closed {
		if window.err != nil {
			return window.err
		}
		return ErrClosed
	}
	if window.credit+size > window.limit {
		return ErrOverGrant
	}
	window.credit += size
	window.broadcastLocked()
	return nil
}

// Close unblocks every waiter and rejects further grants. A nil error is
// reported as ErrClosed.
func (window *Window) Close(err error) {
	window.mu.Lock()
	defer window.mu.Unlock()
	if window.closed {
		return
	}
	window.closed = true
	window.err = err
	window.broadcastLocked()
}

func (window *Window) broadcastLocked() {
	close(window.changed)
	window.changed = make(chan struct{})
}

// InitialCredit converts a receiver's per-stream byte budget into the first
// stream_window_update grant. Credit is capped at the contract ceiling; a
// tiny budget still grants one byte so a sender cannot be stalled forever by a
// misconfigured zero.
func InitialCredit(budget int64) uint32 {
	if budget < 1 {
		return 1
	}
	if budget > contractv1.MaxWindowCreditBytes {
		return contractv1.MaxWindowCreditBytes
	}
	return uint32(budget)
}
