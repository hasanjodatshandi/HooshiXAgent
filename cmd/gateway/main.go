package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/gateway"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gateway:", err)
		os.Exit(1)
	}
}

// stringList collects a repeatable flag value.
type stringList []string

func (list *stringList) String() string { return strings.Join(*list, ",") }

func (list *stringList) Set(value string) error {
	*list = append(*list, value)
	return nil
}

func run() error {
	defaults := gateway.DefaultLimits()
	var trustedProxies stringList
	var (
		listenAddr           = flag.String("listen", "127.0.0.1:8443", "HTTPS/WSS listen address")
		opsListenAddr        = flag.String("ops-listen", "127.0.0.1:9090", "administrative listen address for /healthz, /readyz and /metrics (plaintext; must not be publicly reachable, empty disables the endpoint)")
		logLevel             = flag.String("log-level", "info", "log level: debug or info")
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
		preAuthRate          = flag.Int("preauth-rate", defaults.PreAuthRatePerSecond, "pre-authentication Agent connection rate per trusted peer per second")
		preAuthBurst         = flag.Int("preauth-burst", defaults.PreAuthRateBurst, "pre-authentication Agent connection rate burst per trusted peer")
	)
	flag.Var(&trustedProxies, "trusted-proxy", "IP or CIDR of the public edge that terminates client TLS and may supply the client address in X-Forwarded-For (repeatable)")
	flag.Parse()

	if *tlsCert == "" || *tlsKey == "" {
		return errors.New("-tls-cert and -tls-key are required; plaintext production mode is not supported")
	}
	if *metadataDir == "" {
		return errors.New("-metadata-dir is required")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: gatewayLogLevel(*logLevel)}))
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
	limits.PreAuthRatePerSecond = *preAuthRate
	limits.PreAuthRateBurst = *preAuthBurst
	limits.TrustedProxyPeers = trustedProxies
	serverGateway, err := gateway.New(metadata, gateway.NewJSONLineStatusSink(os.Stdout), limits, logger)
	if err != nil {
		return err
	}
	server := gateway.NewHTTPServer(*listenAddr, serverGateway.Handler(), limits)
	// Operational endpoints are served on their own listener so they can
	// never shadow a tenant route on the public listener.
	var opsServer *http.Server
	if *opsListenAddr != "" {
		opsServer = gateway.NewOpsHTTPServer(*opsListenAddr, serverGateway.OpsHandler(), limits)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)
	go func() {
		logger.Info("gateway starting", "listen", *listenAddr, "metadata_mode", *metadataMode)
		errCh <- server.ListenAndServeTLS(*tlsCert, *tlsKey)
	}()
	if opsServer != nil {
		go func() {
			logger.Info("gateway ops endpoints listening", "listen", *opsListenAddr)
			errCh <- opsServer.ListenAndServe()
		}()
	}

	select {
	case <-ctx.Done():
		serverGateway.BeginDrain()
		return gracefulShutdown(server, opsServer, serverGateway.Close, limits.ShutdownTimeout, logger)
	case err := <-errCh:
		closeCtx, cancel := context.WithTimeout(context.Background(), limits.ShutdownTimeout)
		defer cancel()
		_ = serverGateway.Close(closeCtx)
		if opsServer != nil {
			_ = opsServer.Close()
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, os.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// gracefulShutdown runs the bounded graceful shutdown sequence for a running
// Gateway: draining is entered before the HTTP listeners stop accepting, the
// listeners are then given a bounded window to finish in-flight requests, and
// the tunnels are finally drained. drainTunnels is *gateway.Gateway.Close; it
// is a parameter so the ordering contract below is testable without a live
// Agent.
//
// The tunnel drain runs in its own bounded window rather than inheriting the
// listener window: http.Server.Shutdown spends the whole window waiting for
// in-flight requests, and the Gateway's tunnel drain only starts after it
// returns — it is the step that fails the active streams, which is also what
// releases those in-flight ingress requests. Sharing one window left the drain
// with an already-expired context, reported "gateway drain incomplete: context
// deadline exceeded", and exited 1 after a drain that had in fact completed,
// so restart-on-failure supervisors treated a correct drain as a crash.
func gracefulShutdown(server *http.Server, opsServer *http.Server, drainTunnels func(context.Context) error, timeout time.Duration, logger *slog.Logger) error {
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), timeout)
	defer cancelShutdown()
	serverErr := server.Shutdown(shutdownCtx)
	opsErr := error(nil)
	if opsServer != nil {
		opsErr = opsServer.Shutdown(shutdownCtx)
	}
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), timeout)
	defer cancelDrain()
	gatewayErr := drainTunnels(drainCtx)
	if serverErr != nil {
		// http.Server.Shutdown only ever reports context expiry: the
		// bounded drain window elapsed with connections still open. That
		// is a degraded-but-intentional outcome, not a process failure.
		logger.Warn("http shutdown incomplete", "error", serverErr)
	}
	if opsErr != nil {
		logger.Warn("ops shutdown incomplete", "error", opsErr)
	}
	if gatewayErr != nil {
		logger.Warn("gateway drain incomplete", "error", gatewayErr)
	}
	return shutdownResult(serverErr, opsErr, gatewayErr)
}

// shutdownResult maps the HTTP-server and Gateway drain outcomes onto the
// process exit result. A bounded http.Server.Shutdown timeout is not fatal on
// its own: Shutdown only reports context expiry, while the Gateway drain below
// is the authoritative signal for whether the bounded drain completed.
func shutdownResult(serverErr, opsErr, gatewayErr error) error {
	if gatewayErr != nil {
		return fmt.Errorf("gateway drain incomplete: %w", errors.Join(serverErr, opsErr, gatewayErr))
	}
	return nil
}

// gatewayLogLevel maps the -log-level flag to a slog level.
func gatewayLogLevel(raw string) slog.Level {
	if raw == "debug" {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}
