package svc

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// statusInterval is how often the service supervisor persists
// status.json for the tray app.
const statusInterval = 2 * time.Second

// signalContext returns a context cancelled on interrupt/terminate together
// with its release function. Callers defer the release so the signal handler is
// unregistered when the foreground tool returns, instead of holding a
// discarded stop function that can never be called.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
