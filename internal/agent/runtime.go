package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"time"

	"github.com/coder/websocket"
)

var ErrSessionRevoked = errors.New("agent session revoked")

type Limits struct {
	MaxStreams       int
	MaxQueueFrames   int
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	WriteTimeout     time.Duration
	IdleTimeout      time.Duration
	ReconnectMin     time.Duration
	ReconnectMax     time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		MaxStreams:       64,
		MaxQueueFrames:   16,
		DialTimeout:      5 * time.Second,
		HandshakeTimeout: 10 * time.Second,
		WriteTimeout:     10 * time.Second,
		IdleTimeout:      60 * time.Second,
		ReconnectMin:     time.Second,
		ReconnectMax:     30 * time.Second,
	}
}

func (limits Limits) valid() bool {
	return limits.MaxStreams > 0 && limits.MaxQueueFrames > 0 && limits.DialTimeout > 0 &&
		limits.HandshakeTimeout > 0 && limits.WriteTimeout > 0 && limits.IdleTimeout > 0 &&
		limits.ReconnectMin > 0 && limits.ReconnectMax >= limits.ReconnectMin
}

type Runner struct {
	stateDir string
	limits   Limits
	logger   *slog.Logger
	attempt  func(context.Context) error
}

func NewRunner(stateDir string, limits Limits, logger *slog.Logger) (*Runner, error) {
	normalized, err := NormalizeStateDir(stateDir)
	if err != nil {
		return nil, err
	}
	if !limits.valid() {
		return nil, errors.New("invalid Agent limits")
	}
	if logger == nil {
		logger = slog.Default()
	}
	runner := &Runner{stateDir: normalized, limits: limits, logger: logger}
	runner.attempt = runner.runOnce
	return runner, nil
}

func (runner *Runner) Run(ctx context.Context) error {
	backoff := runner.limits.ReconnectMin
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		sessionStarted := time.Now()
		err := runner.attempt(ctx)
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, ErrSessionRevoked) {
			return err
		}
		if time.Since(sessionStarted) >= 10*time.Second {
			backoff = runner.limits.ReconnectMin
		}
		runner.logger.Warn("agent session ended; reconnecting", "error", sanitizedError(err), "retry_in", backoff.String())
		delay := jittered(backoff)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		backoff *= 2
		if backoff > runner.limits.ReconnectMax {
			backoff = runner.limits.ReconnectMax
		}
	}
}

func (runner *Runner) runOnce(ctx context.Context) error {
	config, err := LoadConfig(runner.stateDir)
	if err != nil {
		return err
	}
	if err := config.ValidateRuntime(); err != nil {
		return err
	}
	store := NewPlatformSecretStore(runner.stateDir)
	_, privateKey, err := LoadOrCreateIdentity(store)
	if err != nil {
		return err
	}
	token, err := LoadSessionToken(store)
	if err != nil {
		return err
	}

	tlsConfig, err := tlsConfigForAgent(config)
	if err != nil {
		return err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	transport.TLSHandshakeTimeout = runner.limits.HandshakeTimeout
	transport.ResponseHeaderTimeout = runner.limits.HandshakeTimeout
	transport.ForceAttemptHTTP2 = false
	httpClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("gateway redirects are not allowed")
		},
	}

	dialCtx, cancel := context.WithTimeout(ctx, runner.limits.HandshakeTimeout)
	conn, _, err := websocket.Dial(dialCtx, config.GatewayURL, &websocket.DialOptions{
		HTTPClient:      httpClient,
		CompressionMode: websocket.CompressionDisabled,
	})
	cancel()
	if err != nil {
		return fmt.Errorf("dial Gateway WSS: %w", err)
	}
	conn.SetReadLimit(24 + 1024*1024)

	sess, err := authenticateAgent(ctx, conn, config, privateKey, token, runner.limits, runner.logger)
	if err != nil {
		conn.CloseNow()
		return err
	}
	runner.logger.Info("agent session authenticated", "device_id", config.DeviceID, "session_id", sess.sessionID, "secret_store", store.Kind())
	return sess.run(ctx)
}

func tlsConfigForAgent(config Config) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if config.CAFile != "" {
		pemData, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read custom CA file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pemData) {
			return nil, errors.New("custom CA file contains no valid certificates")
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, nil
}

func jittered(base time.Duration) time.Duration {
	if base <= 4*time.Millisecond {
		return base
	}
	quarter := base / 4
	return base - quarter/2 + time.Duration(rand.Int64N(int64(quarter)))
}

func sanitizedError(err error) string {
	if err == nil {
		return "session ended"
	}
	return err.Error()
}
