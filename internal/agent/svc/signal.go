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

// signalContext returns a context cancelled on interrupt/terminate.
func signalContext() context.Context {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// Keep stop alive for the process lifetime; foreground tools exit with
	// the process anyway.
	_ = stop
	return ctx
}


