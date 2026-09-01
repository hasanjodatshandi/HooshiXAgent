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
	defaults := gateway.DefaultLimits()
	var (
		listenAddr           = flag.String("listen", "127.0.0.1:8443", "HTTPS/WSS listen address")
		tlsCert              = flag.String("tls-cert", "", "TLS certificate PEM path (required)")
		tlsKey               = flag.String("tls-key", "", "TLS private key PEM path (required)")
		metadataDir          = flag.String("metadata-dir", "", "read-only external metadata root directory (required)")
		metadataMode         = flag.String("metadata-mode", "live", "external metadata mode: live or static compatibility")
		metadataRefresh      = flag.Duration("metadata-refresh-interval", gateway.DefaultMetadataRefreshInterval, "live metadata current-manifest refresh interval")
		metadataMaxAge       = flag.Duration("metadata-max-age", gateway.DefaultMetadataMaxSnapshotAge, "maximum accepted age of a live metadata generation")
		maxAgentSessions     = flag.Int("max-agent-sessions", defaults.MaxAgentSessions, "maximum authenticated Agent sessions")
		maxPendingHandshakes = flag.Int("max-pending-handshakes", defaults.MaxPendingHandshakes, "maximum concurrent Agent handshakes")
		maxStreamQueueBytes  = flag.Int64("max-stream-queue-bytes", defaults.MaxStreamQueueBytes, "maximum queued Agent-to-Gateway bytes per stream")
		maxSessionQueueBytes = flag.Int64("max-session-queue-bytes", defaults.MaxSessionQueueBytes, "maximum queued Agent-to-Gateway bytes per Agent session")
		maxGlobalQueueBytes  = flag.Int64("max-global-queue-bytes", defaults.MaxGlobalQueueBytes, "maximum queued Agent-to-Gateway bytes globally")
		maxIngressInFlight   = flag.Int("max-ingress-inflight", defaults.MaxIngressInFlight, "maximum concurrent public ingress requests")
		maxIngressBytes      = flag.Int64("max-ingress-inflight-bytes", defaults.MaxIngressInFlightBytes, "maximum serialized public ingress bytes globally")
		handshakeRate        = flag.Int("handshake-rate", defaults.HandshakeRatePerSecond, "global Agent handshake rate per second")
		handshakeBurst       = flag.Int("handshake-burst", defaults.HandshakeRateBurst, "global Agent handshake rate burst")
		ingressRate          = flag.Int("ingress-rate", defaults.IngressRatePerSecond, "global public ingress request rate per second")
		ingressBurst         = flag.Int("ingress-burst", defaults.IngressRateBurst, "global public ingress rate burst")
	)
	flag.Parse()

	if *tlsCert == "" || *tlsKey == "" {
		return errors.New("-tls-cert and -tls-key are required; plaintext production mode is not supported")
	}
	if *metadataDir == "" {
		return errors.New("-metadata-dir is required")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var metadata gateway.MetadataSource
	var closeMetadata func()
	switch *metadataMode {
	case "static":
		staticMetadata, err := gateway.LoadSnapshotDirectory(*metadataDir)
		if err != nil {
			return fmt.Errorf("load external metadata snapshot: %w", err)
		}
		metadata = staticMetadata
	case "live":
		liveMetadata, err := gateway.NewLiveMetadata(*metadataDir, gateway.LiveMetadataOptions{
			RefreshInterval: *metadataRefresh,
			MaxSnapshotAge:  *metadataMaxAge,
			Logger:          logger,
		})
		if err != nil {
			return fmt.Errorf("initialize live external metadata projection: %w", err)
		}
		metadata = liveMetadata
		closeMetadata = func() { _ = liveMetadata.Close() }
	default:
		return fmt.Errorf("unsupported -metadata-mode %q; expected static or live", *metadataMode)
	}
	if closeMetadata != nil {
		defer closeMetadata()
	}

	limits := defaults
	limits.MaxAgentSessions = *maxAgentSessions
	limits.MaxPendingHandshakes = *maxPendingHandshakes
	limits.MaxStreamQueueBytes = *maxStreamQueueBytes
	limits.MaxSessionQueueBytes = *maxSessionQueueBytes
	limits.MaxGlobalQueueBytes = *maxGlobalQueueBytes
	limits.MaxIngressInFlight = *maxIngressInFlight
	limits.MaxIngressInFlightBytes = *maxIngressBytes
	limits.HandshakeRatePerSecond = *handshakeRate
	limits.HandshakeRateBurst = *handshakeBurst
	limits.IngressRatePerSecond = *ingressRate
	limits.IngressRateBurst = *ingressBurst
	serverGateway, err := gateway.New(metadata, gateway.NewJSONLineStatusSink(os.Stdout), limits, logger)
	if err != nil {
		return err
	}
	server := gateway.NewHTTPServer(*listenAddr, serverGateway.Handler(), limits)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("gateway starting", "listen", *listenAddr, "metadata_mode", *metadataMode)
		errCh <- server.ListenAndServeTLS(*tlsCert, *tlsKey)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), limits.ShutdownTimeout)
		defer cancel()
		serverGateway.BeginDrain()
		serverErr := server.Shutdown(shutdownCtx)
		gatewayErr := serverGateway.Close(shutdownCtx)
		if gatewayErr != nil {
			logger.Warn("gateway drain incomplete", "error", gatewayErr)
		}
		if serverErr != nil {
			return fmt.Errorf("shutdown: %w", serverErr)
		}
		return nil
	case err := <-errCh:
		closeCtx, cancel := context.WithTimeout(context.Background(), limits.ShutdownTimeout)
		defer cancel()
		_ = serverGateway.Close(closeCtx)
		if errors.Is(err, context.Canceled) || errors.Is(err, os.ErrClosed) {
			return nil
		}
		return err
	}
}
