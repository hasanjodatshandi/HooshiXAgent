package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/gateway"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gateway:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listenAddr  = flag.String("listen", "127.0.0.1:8443", "HTTPS/WSS listen address")
		tlsCert     = flag.String("tls-cert", "", "TLS certificate PEM path (required)")
		tlsKey      = flag.String("tls-key", "", "TLS private key PEM path (required)")
		metadataDir = flag.String("metadata-dir", "", "read-only external metadata snapshot directory (required)")
	)
	flag.Parse()

	if *tlsCert == "" || *tlsKey == "" {
		return errors.New("-tls-cert and -tls-key are required; plaintext production mode is not supported")
	}
	if *metadataDir == "" {
		return errors.New("-metadata-dir is required")
	}

	metadata, err := gateway.LoadSnapshotDirectory(*metadataDir)
	if err != nil {
		return fmt.Errorf("load external metadata snapshot: %w", err)
	}
	limits := gateway.DefaultLimits()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	serverGateway, err := gateway.New(metadata, gateway.NewJSONLineStatusSink(os.Stdout), limits, logger)
	if err != nil {
		return err
	}
	server := gateway.NewHTTPServer(*listenAddr, serverGateway.Handler(), limits)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("gateway starting", "listen", *listenAddr)
		errCh <- server.ListenAndServeTLS(*tlsCert, *tlsKey)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), limits.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, context.Canceled) || errors.Is(err, os.ErrClosed) {
			return nil
		}
		return err
	}
}
