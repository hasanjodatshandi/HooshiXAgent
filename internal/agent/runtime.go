package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/coder/websocket"
)

var (
	ErrSessionRevoked        = errors.New("agent session revoked")
	ErrPermanentAgentFailure = errors.New("permanent Agent failure")
	errGatewayRedirect       = errors.New("gateway redirects are not allowed")

	sensitiveJSONPattern       = regexp.MustCompile(`(?i)("(?:session_token|access_token|refresh_token|credential|secret)"\s*:\s*")[^"]*`)
	sensitiveAssignmentPattern = regexp.MustCompile(`(?i)((?:session[_ -]?token|access[_ -]?token|refresh[_ -]?token|credential|secret)\s*[:=]\s*["']?)[^"',\s]+`)
	sensitiveSpacePattern      = regexp.MustCompile(`(?i)((?:session[_ -]?token|access[_ -]?token|refresh[_ -]?token|credential|secret)\s+)[A-Za-z0-9._~+/=-]{8,}`)
	bearerPattern              = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}`)
)

type Limits struct {
	MaxStreams           int
	MaxQueueFrames       int
	MaxStreamQueueBytes  int64
	MaxSessionQueueBytes int64
	DialTimeout          time.Duration
	HandshakeTimeout     time.Duration
	WriteTimeout         time.Duration
	IdleTimeout          time.Duration
	ReconnectMin         time.Duration
	ReconnectMax         time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		MaxStreams:           64,
		MaxQueueFrames:       16,
		MaxStreamQueueBytes:  2 << 20,
		MaxSessionQueueBytes: 8 << 20,
		DialTimeout:          5 * time.Second,
		HandshakeTimeout:     10 * time.Second,
		WriteTimeout:         10 * time.Second,
		IdleTimeout:          60 * time.Second,
		ReconnectMin:         time.Second,
		ReconnectMax:         30 * time.Second,
	}
}

func (limits Limits) valid() bool {
	return limits.MaxStreams > 0 && limits.MaxQueueFrames > 0 &&
		limits.MaxStreamQueueBytes > 0 && limits.MaxSessionQueueBytes >= limits.MaxStreamQueueBytes && limits.DialTimeout > 0 &&
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
		if errors.Is(err, ErrSessionRevoked) || errors.Is(err, ErrPermanentAgentFailure) {
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
		return permanentAgentFailure(err)
	}
	if err := config.ValidateRuntime(); err != nil {
		return permanentAgentFailure(err)
	}
	store := NewPlatformSecretStore(runner.stateDir)
	_, privateKey, err := LoadIdentity(store)
	if err != nil {
		return permanentAgentFailure(err)
	}
	token, err := LoadSessionToken(store)
	if err != nil {
		return permanentAgentFailure(err)
	}

	tlsConfig, err := tlsConfigForAgent(config)
	if err != nil {
		return permanentAgentFailure(err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	transport.TLSHandshakeTimeout = runner.limits.HandshakeTimeout
	transport.ResponseHeaderTimeout = runner.limits.HandshakeTimeout
	transport.ForceAttemptHTTP2 = false
	httpClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errGatewayRedirect
		},
	}

	dialCtx, cancel := context.WithTimeout(ctx, runner.limits.HandshakeTimeout)
	conn, response, err := websocket.Dial(dialCtx, config.GatewayURL, &websocket.DialOptions{
		HTTPClient:      httpClient,
		CompressionMode: websocket.CompressionDisabled,
	})
	cancel()
	if err != nil {
		err = protectError(fmt.Errorf("dial Gateway WSS: %w", err), token)
		if permanentDialError(err, response) {
			return permanentAgentFailure(err)
		}
		return err
	}
	conn.SetReadLimit(24 + 1024*1024)

	sess, err := authenticateAgent(ctx, conn, config, privateKey, token, runner.limits, runner.logger)
	if err != nil {
		conn.CloseNow()
		err = protectError(err, token)
		if permanentRemoteSessionError(err) {
			return permanentAgentFailure(err)
		}
		return err
	}
	runner.logger.Info("agent session authenticated", "device_id", config.DeviceID, "session_id", sess.sessionID, "secret_store", store.Kind())
	err = protectError(sess.run(ctx), token)
	if errors.Is(err, ErrSessionRevoked) {
		return err
	}
	if permanentRemoteSessionError(err) {
		return permanentAgentFailure(err)
	}
	return err
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

func permanentAgentFailure(err error) error {
	if err == nil || errors.Is(err, ErrPermanentAgentFailure) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrPermanentAgentFailure, err)
}

func permanentDialError(err error, response *http.Response) bool {
	if errors.Is(err, errGatewayRedirect) {
		return true
	}
	if response != nil && response.StatusCode >= 400 && response.StatusCode < 500 {
		switch response.StatusCode {
		case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
			return false
		default:
			return true
		}
	}
	var certificateError *tls.CertificateVerificationError
	return errors.As(err, &certificateError)
}

func permanentRemoteSessionError(err error) bool {
	if err == nil {
		return false
	}
	switch status := websocket.CloseStatus(err); status {
	case websocket.StatusProtocolError, websocket.StatusUnsupportedData, websocket.StatusInvalidFramePayloadData, websocket.StatusPolicyViolation, websocket.StatusMessageTooBig, websocket.StatusMandatoryExtension:
		return true
	case websocket.StatusNormalClosure, websocket.StatusGoingAway, websocket.StatusNoStatusRcvd, websocket.StatusAbnormalClosure, websocket.StatusInternalError, websocket.StatusServiceRestart, websocket.StatusTryAgainLater, websocket.StatusBadGateway:
		return false
	default:
		if status != -1 {
			return true
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return false
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		return false
	}
	// After a WebSocket is established, non-transport errors are local validation of
	// peer protocol/authentication behavior and cannot be repaired by immediate retry.
	return true
}

type protectedRuntimeError struct {
	err     error
	message string
}

func (err *protectedRuntimeError) Error() string { return err.message }
func (err *protectedRuntimeError) Unwrap() error { return err.err }

func protectError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	return &protectedRuntimeError{err: err, message: sanitizeErrorMessage(err.Error(), secrets...)}
}

func sanitizedError(err error) string {
	if err == nil {
		return "session ended"
	}
	return sanitizeErrorMessage(err.Error())
}

func sanitizeErrorMessage(message string, secrets ...string) string {
	for _, secret := range secrets {
		if len(secret) >= 8 {
			message = strings.ReplaceAll(message, secret, "<redacted>")
		}
	}
	message = sensitiveJSONPattern.ReplaceAllString(message, `${1}<redacted>`)
	message = sensitiveAssignmentPattern.ReplaceAllString(message, `${1}<redacted>`)
	message = sensitiveSpacePattern.ReplaceAllString(message, `${1}<redacted>`)
	message = bearerPattern.ReplaceAllString(message, `${1}<redacted>`)
	return message
}
