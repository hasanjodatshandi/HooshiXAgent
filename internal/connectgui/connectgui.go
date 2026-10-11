// Package connectgui is the state machine behind the HooshiX Connect app. It
// turns a pasted connect bundle into a running loopback Connector and keeps one
// current Status a GUI can render from any thread. It owns no window code, so
// the whole session lifecycle is testable without Windows.
package connectgui

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/connector"
)

// State is where the session is.
type State string

const (
	StateIdle      State = "idle"
	StateListening State = "listening"
	StateStopped   State = "stopped"
	StateFailed    State = "failed"
)

// Status is the snapshot the window renders.
type Status struct {
	State    State
	Listen   string
	Protocol string
	Message  string
}

// App runs at most one Connector session.
type App struct {
	// listenTCP and listenUDP are seams so a test can prove the bind/report/
	// teardown path against a real loopback socket without a Gateway.
	listenTCP func(network, address string) (net.Listener, error)
	listenUDP func(network, address string) (net.PacketConn, error)

	mu     sync.Mutex
	status Status
	cancel context.CancelFunc
	done   chan struct{}
}

func New() *App {
	return &App{
		listenTCP: net.Listen,
		listenUDP: net.ListenPacket,
		status:    Status{State: StateIdle, Message: "paste a connect bundle and press Connect"},
	}
}

// Status returns the current snapshot.
func (a *App) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status
}

// Connect parses a bundle and starts serving loopback traffic for it. Binding
// failures are returned synchronously: the operator needs the reason in the
// window, not in a log file they were never promised.
func (a *App) Connect(rawBundle string) error {
	bundle, err := connector.ParseBundle(rawBundle)
	if err != nil {
		a.recordFailure(err)
		return err
	}
	config := bundle.Config(connector.DefaultConfig())

	// The one-session check, the bind, and the ownership bookkeeping all happen
	// under one lock: binding outside it let two concurrent Connect calls both
	// see "no session" and leak the second loopback socket.
	a.mu.Lock()
	if a.cancel != nil {
		a.mu.Unlock()
		err := errors.New("already connected — press Disconnect first")
		a.recordFailure(err)
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	stream, packet, address, err := a.bind(config)
	if err != nil {
		a.mu.Unlock()
		cancel()
		a.recordFailure(err)
		return err
	}
	stopped := make(chan struct{})
	a.cancel = cancel
	a.done = stopped
	a.status = Status{
		State:    StateListening,
		Listen:   address,
		Protocol: config.Protocol,
		Message:  "tunnel ready — open your client against " + address,
	}
	a.mu.Unlock()

	logger := slog.New(&statusHandler{app: a})
	go func() {
		defer close(stopped)
		var serveErr error
		if config.Protocol == "udp" {
			serveErr = connector.ServeUDP(ctx, packet, config, logger)
		} else {
			serveErr = connector.Serve(ctx, stream, config, logger)
		}
		a.finish(ctx, cancel, serveErr)
	}()
	return nil
}

// bind opens the loopback socket for the session. The caller holds a.mu.
func (a *App) bind(config connector.Config) (net.Listener, net.PacketConn, string, error) {
	if config.Protocol == "udp" {
		packet, err := a.listenUDP("udp", config.ListenAddress)
		if err != nil {
			return nil, nil, "", fmt.Errorf("listen on %s: %w", config.ListenAddress, err)
		}
		address := packet.LocalAddr().String()
		if !loopbackAddress(address) {
			_ = packet.Close()
			return nil, nil, "", errors.New("connector listener must be bound to loopback")
		}
		return nil, packet, address, nil
	}
	stream, err := a.listenTCP("tcp", config.ListenAddress)
	if err != nil {
		return nil, nil, "", fmt.Errorf("listen on %s: %w", config.ListenAddress, err)
	}
	address := stream.Addr().String()
	if !loopbackAddress(address) {
		_ = stream.Close()
		return nil, nil, "", errors.New("connector listener must be bound to loopback")
	}
	return stream, nil, address, nil
}

// Disconnect stops the active session, if any, and waits for it to release the
// loopback port so a reconnect on the same address cannot race the old socket.
func (a *App) Disconnect() {
	a.mu.Lock()
	cancel, done := a.cancel, a.done
	a.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
}

func (a *App) finish(ctx context.Context, cancel context.CancelFunc, serveErr error) {
	cancel()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cancel = nil
	a.done = nil
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		a.status = Status{State: StateStopped, Protocol: a.status.Protocol, Message: "disconnected"}
	case serveErr != nil:
		a.status = Status{State: StateFailed, Protocol: a.status.Protocol, Message: serveErr.Error()}
	default:
		a.status = Status{State: StateStopped, Protocol: a.status.Protocol, Message: "tunnel closed"}
	}
}

func (a *App) recordFailure(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.status.State == StateListening {
		return
	}
	a.status = Status{State: StateFailed, Protocol: a.status.Protocol, Message: err.Error()}
}

// recordFlowEvent keeps per-flow warnings visible without ending the session:
// one failed flow is a message, not a state change, because the listener is
// still accepting the next connection.
func (a *App) recordFlowEvent(message string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.status.State == StateListening {
		a.status.Message = message
	}
}

func loopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// statusHandler forwards Connector warnings into the app status.
type statusHandler struct {
	app *App
}

func (h *statusHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *statusHandler) Handle(_ context.Context, record slog.Record) error {
	if record.Level < slog.LevelWarn {
		return nil
	}
	message := record.Message
	record.Attrs(func(attribute slog.Attr) bool {
		if attribute.Key == "error" {
			message = message + ": " + attribute.Value.String()
			return false
		}
		return true
	})
	h.app.recordFlowEvent(message)
	return nil
}
func (h *statusHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *statusHandler) WithGroup(string) slog.Handler      { return h }
