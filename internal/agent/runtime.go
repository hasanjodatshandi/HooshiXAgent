package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent/tunnelstates"
	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
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

	// health carries the connection health state machine and reconnect
	// counter required by the tunnel reliability phase. It is observational
	// only and never authorization authority. The aggregate derives the
	// combined multi-tunnel view (Phase 3 HA) from this machine today.
	health     *tunnelstates.Machine
	aggregate  *tunnelstates.Aggregate
	reconnects atomic.Int64

	// resumable holds the last authenticated session ID for the Phase-2
	// resume fast path. It is only set after a fully authenticated session
	// and cleared whenever resume is rejected so the Agent falls back to a
	// full handshake.
	resumable atomic.Value // string

	// failoverIndex tracks the next gateway candidate for the Phase-3 HA
	// failover schedule. It advances only on dial failure so a healthy
	// primary never rotates.
	failoverIndex atomic.Int32
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
	runner := &Runner{stateDir: normalized, limits: limits, logger: logger, health: tunnelstates.New()}
	runner.aggregate = tunnelstates.NewAggregate(runner.health)
	runner.attempt = runner.runOnce
	return runner, nil
}

// ResumableSessionID returns the session ID eligible for the resume fast
// path, or "" after resume was rejected or no session was established.
func (runner *Runner) ResumableSessionID() string {
	if value, ok := runner.resumable.Load().(string); ok {
		return value
	}
	return ""
}

func (runner *Runner) storeResumable(sessionID string) {
	runner.resumable.Store(sessionID)
}

// HealthState returns the current aggregate connection health state name
// and whether it is terminal. Exposed for status/diagnostics only.
func (runner *Runner) HealthState() (string, bool) {
	state, terminal, _ := runner.aggregate.Observability()
	return state, terminal
}

// HealthyTunnel reports whether the aggregate view currently has a serving
// tunnel. Exposed for status/diagnostics only.
func (runner *Runner) HealthyTunnel() bool {
	return runner.aggregate.Healthy()
}

// ReconnectCount returns the number of completed reconnect cycles since
// process start. Exposed for status/diagnostics only.
func (runner *Runner) ReconnectCount() int64 {
	return runner.reconnects.Load()
}

func (runner *Runner) Run(ctx context.Context) error {
	backoff := runner.limits.ReconnectMin
	for {
		if err := ctx.Err(); err != nil {
			_ = runner.health.Transition(tunnelstates.Shutdown)
			return nil
		}
		if err := runner.health.Transition(tunnelstates.Connecting); err != nil {
			runner.logger.Warn("agent health transition rejected", "error", err)
		}
		sessionStarted := time.Now()
		err := runner.attempt(ctx)
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			_ = runner.health.Transition(tunnelstates.Shutdown)
			return nil
		}
		if errors.Is(err, ErrSessionRevoked) || errors.Is(err, ErrPermanentAgentFailure) {
			if errors.Is(err, ErrSessionRevoked) {
				_ = runner.health.Transition(tunnelstates.Revoked)
			} else {
				_ = runner.health.Transition(tunnelstates.Shutdown)
			}
			return err
		}
		if time.Since(sessionStarted) >= 10*time.Second {
			backoff = runner.limits.ReconnectMin
		}
		if errors.Is(err, errResumeRejected) {
			// The Gateway rejected the resume fast path and closed the
			// transport: retry immediately with a full handshake instead of
			// waiting out a reconnect backoff.
			runner.reconnects.Add(1)
			if transitionErr := runner.health.Transition(tunnelstates.Reconnecting); transitionErr != nil {
				runner.logger.Warn("agent health transition rejected", "error", transitionErr)
			}
			continue
		}
		runner.reconnects.Add(1)
		if err := runner.health.Transition(tunnelstates.Reconnecting); err != nil {
			runner.logger.Warn("agent health transition rejected", "error", err)
		}
		runner.logger.Warn("agent session ended; reconnecting", "error", sanitizedError(err), "retry_in", backoff.String(), "reconnects", runner.ReconnectCount())
		delay := jittered(backoff)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = runner.health.Transition(tunnelstates.Shutdown)
			return nil
		case <-timer.C:
		}
		backoff *= 2
		if backoff > runner.limits.ReconnectMax {
			backoff = runner.limits.ReconnectMax
		}
	}
}

// dialWithFailover dials the configured gateway candidates in bounded
// failover order. It returns the URL that answered plus the live connection.
// The schedule starts at the persisted primary; on failure the next candidate
// is tried until one answers or all fail with the last error. Permanent dial
// errors (redirects, 4xx policy) abort immediately without trying aliases.
func (runner *Runner) dialWithFailover(ctx context.Context, config Config, httpClient *http.Client) (string, *websocket.Conn, *http.Response, error) {
	candidates := config.GatewayCandidates()
	if len(candidates) == 0 {
		return "", nil, nil, errors.New("no gateway URL configured")
	}
	start := int(runner.failoverIndex.Load()) % len(candidates)
	var lastErr error
	var lastResponse *http.Response
	for offset := 0; offset < len(candidates); offset++ {
		index := (start + offset) % len(candidates)
		candidate := candidates[index]
		dialCtx, cancel := context.WithTimeout(ctx, runner.limits.HandshakeTimeout)
		conn, response, err := websocket.Dial(dialCtx, candidate, &websocket.DialOptions{
			HTTPClient:      httpClient,
			CompressionMode: websocket.CompressionDisabled,
		})
		cancel()
		if err == nil {
			runner.failoverIndex.Store(int32(index))
			return candidate, conn, nil, nil
		}
		lastErr = fmt.Errorf("dial Gateway WSS %s: %w", candidate, err)
		lastResponse = response
		if permanentDialError(err, response) {
			// A policy-level rejection (redirect, TLS trust, hard 4xx) is a
			// configuration/security signal, not a per-endpoint outage: stop
			// before rotating through aliases.
			return "", nil, response, lastErr
		}
		runner.logger.Warn("gateway candidate failed; trying next", "gateway", candidate, "error", sanitizedError(lastErr))
	}
	// Every candidate failed: advance the schedule so the next bounded
	// reconnect attempt starts from the next candidate instead of retrying
	// the same dead primary first.
	runner.failoverIndex.Store(int32((start + 1) % len(candidates)))
	return "", nil, lastResponse, lastErr
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
	gatewayURL, conn, response, err := runner.dialWithFailover(dialCtx, config, httpClient)
	cancel()
	if err != nil {
		err = protectError(err, token)
		if permanentDialError(err, response) {
			return permanentAgentFailure(err)
		}
		return err
	}
	conn.SetReadLimit(24 + 1024*1024)

	sess, err := runner.authenticateOrResume(ctx, conn, config, privateKey, token)
	if err != nil {
		conn.CloseNow()
		if errors.Is(err, errResumeRejected) {
			// Resume was rejected (session gone, gateway restarted, key
			// rotated): the transport is already closed by the Gateway, so
			// return the sentinel to the reconnect loop for an immediate
			// full-handshake retry on a fresh connection.
			runner.storeResumable("")
			runner.logger.Info("agent resume rejected; retrying with full handshake")
			return err
		}
		err = protectError(err, token)
		if permanentRemoteSessionError(err) {
			return permanentAgentFailure(err)
		}
		return err
	}
	if err := runner.health.Transition(tunnelstates.Connected); err != nil {
		runner.logger.Warn("agent health transition rejected", "error", err)
	}
	if runner.ReconnectCount() > 0 {
		sess.observeReconnect()
	}
	runner.storeResumable(sess.sessionID)
	runner.logger.Info("agent session authenticated", "gateway", gatewayURL, "device_id", config.DeviceID, "session_id", sess.sessionID, "secret_store", store.Kind(), "health", runner.health.Current().String())
	err = protectError(sess.run(ctx), token)
	if errors.Is(err, ErrSessionRevoked) {
		return err
	}
	if permanentRemoteSessionError(err) {
		return permanentAgentFailure(err)
	}
	return err
}

// errResumeRejected signals the Gateway declined the resume fast path and
// the Agent must fall back to the full client_hello handshake.
var errResumeRejected = errors.New("agent session resume rejected")

// authenticateOrResume tries the Phase-2 resume fast path first when a
// previous session ID is available, then falls back to the caller for a full
// handshake on rejection. A successful resume inherits the previous session
// ID and continues the outbound sequence without a challenge round trip.
func (runner *Runner) authenticateOrResume(ctx context.Context, conn *websocket.Conn, config Config, privateKey ed25519.PrivateKey, token string) (*agentSession, error) {
	previous := runner.ResumableSessionID()
	if previous == "" {
		return authenticateAgent(ctx, conn, config, privateKey, token, runner.limits, runner.logger)
	}

	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	resume := contractv1.ResumeSession{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "resume_session",
		DeviceID:        config.DeviceID,
		AuthorizationID: config.AuthorizationID,
		TokenID:         config.TokenID,
		SessionID:       previous,
		ResumeNonce:     nonce,
	}
	signature := ed25519.Sign(privateKey, contractv1.ResumeTranscript(resume))
	resume.Signature = base64.RawURLEncoding.EncodeToString(signature)
	if err := writeInitialControl(ctx, conn, 1, resume); err != nil {
		return nil, err
	}

	var inbound contractv1.SequenceTracker
	reply, err := readAgentFrame(ctx, conn)
	if err != nil {
		// The Gateway signals an unavailable resume by closing the
		// WebSocket with TryAgainLater before any session frame. That close
		// reason is exactly the resume-rejection fallback signal.
		if websocket.CloseStatus(err) == websocket.StatusTryAgainLater ||
			errors.Is(err, errResumeRejected) {
			return nil, errResumeRejected
		}
		return nil, err
	}
	if err := inbound.Accept(reply.Sequence); err != nil {
		return nil, err
	}
	if reply.Sequence != 1 || reply.Kind != contractv1.KindControl || reply.StreamID != 0 {
		return nil, errors.New("invalid resume reply frame")
	}
	if err := contractv1.ValidateControlPayload(reply.Payload, 0, time.Now().UTC()); err != nil {
		return nil, err
	}
	var envelope struct {
		MessageType string `json:"message_type"`
	}
	if err := json.Unmarshal(reply.Payload, &envelope); err != nil {
		return nil, err
	}
	if envelope.MessageType != "session_resumed" {
		return nil, errResumeRejected
	}
	var resumed contractv1.SessionResumed
	if err := json.Unmarshal(reply.Payload, &resumed); err != nil {
		return nil, err
	}
	if resumed.SessionID != previous {
		return nil, errors.New("session_resumed ID mismatch")
	}

	sess := newResumedAgentSession(conn, config, runner.limits, runner.logger, previous, inbound, resumed.NextSequence-1)
	runner.logger.Info("agent session resumed", "device_id", config.DeviceID, "session_id", previous, "next_sequence", resumed.NextSequence)
	return sess, nil
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
