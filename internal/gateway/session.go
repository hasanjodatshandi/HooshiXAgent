package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

type session struct {
	gateway                *Gateway
	conn                   *websocket.Conn
	deviceID               string
	sessionID              string
	authorizationID        string
	tokenID                string
	authorizationExpiresAt time.Time

	inbound    contractv1.SequenceTracker
	outbound   atomic.Uint64
	lastSeen   atomic.Int64
	authorized atomic.Bool

	// Observability counters (Phase 5). Bounded aggregate telemetry only:
	// never authorization, routing, or business authority. Byte counters live
	// on gatewayResources because they are process-lifetime monotonic.
	pingLatency atomic.Int64 // last heartbeat round-trip in nanoseconds
	pendingPing atomic.Value // pendingPing{id, sentAt} of the last outbound ping

	// resumeChallenge is the per-transport resume proof the Gateway issued to
	// the Agent over this transport (session_ready / session_resumed). A
	// resume_session must present this exact value bound into its signature,
	// and it is rotated on every accepted resume, so a captured resume frame
	// is not a bearer token for the lifetime of the session.
	resumeChallenge atomic.Value // string

	// resumeArmed enforces one-shot replay protection for resume_session:
	// an accepted resume must be explicitly rearmed by the authenticated
	// transport before another resume is allowed on this session identity.
	// A replayed (captured) resume frame can therefore never replace the
	// live connection a second time.
	resumeArmed atomic.Bool

	controlWrites              chan sessionWriteRequest
	dataWrites                 chan sessionWriteRequest
	writeMessage               func(context.Context, []byte) error
	mu                         sync.Mutex
	streams                    map[uint32]*stream
	queueBudget                *byteBudget
	nextID                     uint32
	done                       chan struct{}
	doneOnce                   sync.Once
	closeOnce                  sync.Once
	forceCloseOnce             sync.Once
	closeConn                  func(websocket.StatusCode, string) error
	closeNowConn               func() error
	authorizationTerminateOnce sync.Once
}

// pendingPing pairs an outbound heartbeat ping ID with its send time so the
// matching pong can be identified exactly (telemetry correctness).
type pendingPing struct {
	id     string
	sentAt time.Time
}

// protocolCloseError pairs a session-fatal error with the WebSocket close code
// the protocol close-code table assigns to its cause
// (contracts/v1/tunnel-protocol.md Section 11c).
type protocolCloseError struct {
	code   websocket.StatusCode
	reason string
	err    error
}

func (e *protocolCloseError) Error() string { return e.err.Error() }
func (e *protocolCloseError) Unwrap() error { return e.err }

func closeViolation(code websocket.StatusCode, reason string, err error) error {
	return &protocolCloseError{code: code, reason: reason, err: err}
}

// closeCodeFor resolves the close code a terminal session error obliges the
// Gateway to send, falling back when the error carries no protocol
// classification (a transport failure, which is not a peer violation).
func closeCodeFor(err error, fallback websocket.StatusCode, fallbackReason string) (websocket.StatusCode, string) {
	var protocolErr *protocolCloseError
	if errors.As(err, &protocolErr) {
		return protocolErr.code, protocolErr.reason
	}
	return fallback, fallbackReason
}

func newSession(gateway *Gateway, conn *websocket.Conn, deviceID, sessionID, authorizationID, tokenID string, authorizationExpiresAt time.Time, inbound contractv1.SequenceTracker, lastOutbound uint64, resumeChallenge string) *session {
	sess := &session{
		gateway:                gateway,
		conn:                   conn,
		deviceID:               deviceID,
		sessionID:              sessionID,
		authorizationID:        authorizationID,
		tokenID:                tokenID,
		authorizationExpiresAt: authorizationExpiresAt,
		inbound:                inbound,
		streams:                make(map[uint32]*stream),
		queueBudget:            newByteBudget(gateway.limits.MaxSessionQueueBytes),
		nextID:                 1,
		done:                   make(chan struct{}),
		controlWrites:          make(chan sessionWriteRequest, 32),
		dataWrites:             make(chan sessionWriteRequest, 2),
	}
	sess.writeMessage = func(ctx context.Context, frame []byte) error {
		return conn.Write(ctx, websocket.MessageBinary, frame)
	}
	sess.closeConn = conn.Close
	sess.closeNowConn = conn.CloseNow
	sess.outbound.Store(lastOutbound)
	sess.lastSeen.Store(time.Now().UnixNano())
	sess.authorized.Store(true)
	sess.resumeChallenge.Store(resumeChallenge)
	// A fresh full handshake arms the one-shot resume slot for this new
	// session identity.
	sess.resumeArmed.Store(true)
	go sess.writeLoop()
	return sess
}

// currentResumeChallenge returns the resume proof the Gateway last issued for
// this session identity.
func (sess *session) currentResumeChallenge() string {
	if value, ok := sess.resumeChallenge.Load().(string); ok {
		return value
	}
	return ""
}

// resumeInto binds this session's identity to a replacement WebSocket after
// a successful resume_session. The stream table starts empty (streams were
// bound to the lost transport); sequence numbering restarts on the new
// connection per ADR-0007's independent per-direction rule, so the resumed
// control writer continues from the fresh handshake frame. resumeChallenge is
// the freshly rotated proof for the *next* resume on this identity. It returns
// nil when the original session is no longer resumable.
func (sess *session) resumeInto(conn *websocket.Conn, inbound contractv1.SequenceTracker, resumeChallenge string) *session {
	if sess == nil || !sess.authorized.Load() {
		return nil
	}
	// nextID is guarded by sess.mu in openStream; reading it here without
	// the mutex is a data race (Go memory model: unsynchronized read while
	// concurrent ingress handlers may be allocating stream IDs).
	sess.mu.Lock()
	resumeNextID := sess.nextID
	sess.mu.Unlock()
	resumed := &session{
		gateway:                sess.gateway,
		conn:                   conn,
		deviceID:               sess.deviceID,
		sessionID:              sess.sessionID,
		authorizationID:        sess.authorizationID,
		tokenID:                sess.tokenID,
		authorizationExpiresAt: sess.authorizationExpiresAt,
		inbound:                inbound,
		streams:                make(map[uint32]*stream),
		queueBudget:            newByteBudget(sess.gateway.limits.MaxSessionQueueBytes),
		nextID:                 resumeNextID,
		done:                   make(chan struct{}),
		controlWrites:          make(chan sessionWriteRequest, 32),
		dataWrites:             make(chan sessionWriteRequest, 2),
	}
	resumed.writeMessage = func(ctx context.Context, frame []byte) error {
		return conn.Write(ctx, websocket.MessageBinary, frame)
	}
	resumed.closeConn = conn.Close
	resumed.closeNowConn = conn.CloseNow
	resumed.outbound.Store(0)
	resumed.lastSeen.Store(time.Now().UnixNano())
	resumed.authorized.Store(true)
	resumed.resumeChallenge.Store(resumeChallenge)
	// The fresh transport may itself be resumed later (a later network
	// drop must not lock the device out of the fast path), so the resumed
	// session starts armed for exactly one future resume.
	resumed.resumeArmed.Store(true)
	go resumed.writeLoop()
	return resumed
}

func (sess *session) run(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	go sess.heartbeatLoop(ctx)
	go sess.authorizationExpiryLoop(ctx)

	for {
		frame, err := readProtocolFrame(ctx, sess.conn)
		if err != nil {
			sess.failAll(err)
			code, reason := closeCodeFor(err, websocket.StatusNormalClosure, "session ended")
			sess.close(code, reason)
			return
		}
		if err := sess.inbound.Accept(frame.Sequence); err != nil {
			sess.failAll(err)
			// Non-contiguous/replayed sequence values are a protocol error,
			// not a policy violation (contracts/v1/tunnel-protocol.md 11c).
			sess.close(websocket.StatusProtocolError, "sequence violation")
			return
		}
		sess.lastSeen.Store(time.Now().UnixNano())

		switch frame.Kind {
		case contractv1.KindControl:
			if err := sess.handleControl(ctx, frame); err != nil {
				sess.failAll(err)
				code, reason := closeCodeFor(err, websocket.StatusPolicyViolation, "control violation")
				sess.close(code, reason)
				return
			}
		case contractv1.KindData:
			if err := sess.handleData(frame); err != nil {
				sess.failAll(err)
				sess.close(websocket.StatusPolicyViolation, "data violation")
				return
			}
		default:
			sess.failAll(errors.New("unknown frame kind"))
			sess.close(websocket.StatusProtocolError, "unknown frame kind")
			return
		}
	}
}

func (sess *session) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(sess.gateway.limits.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sess.done:
			return
		case <-ticker.C:
			now := time.Now().UTC()
			reasonCode, authErr := sess.revalidateAuthorization(ctx, now)
			if authErr != nil {
				sess.terminateAuthorization(ctx, reasonCode, authErr)
				return
			}
			lastSeen := time.Unix(0, sess.lastSeen.Load())
			if time.Since(lastSeen) > sess.gateway.limits.IdleTimeout {
				sess.failAll(errors.New("agent session idle timeout"))
				sess.close(websocket.StatusPolicyViolation, "idle timeout")
				return
			}
			pingID, err := sess.gateway.newID("ping")
			if err != nil {
				sess.failAll(err)
				sess.close(websocket.StatusInternalError, "heartbeat entropy unavailable")
				return
			}
			ping := contractv1.Heartbeat{
				ContractVersion: contractv1.ProtocolVersion,
				MessageType:     "ping",
				PingID:          pingID,
				SentAt:          time.Now().UTC().Format(time.RFC3339),
			}
			pingCtx, cancel := context.WithTimeout(ctx, sess.gateway.limits.WriteTimeout)
			err = sess.sendControl(pingCtx, 0, ping)
			cancel()
			if err != nil {
				sess.failAll(err)
				sess.close(websocket.StatusInternalError, "heartbeat write failed")
				return
			}
			// Arm the latency observation window for the matching pong.
			// Store the ping ID so a stale/late pong from an earlier ping
			// cannot be paired with the newest send time (which would skew
			// the latency telemetry last-writer-wins).
			sess.pendingPing.Store(pendingPing{id: pingID, sentAt: time.Now()})
		}
	}
}

func (sess *session) authorizationExpiryLoop(ctx context.Context) {
	delay := time.Until(sess.authorizationExpiresAt)
	if delay <= 0 {
		sess.terminateAuthorization(ctx, "expired", errors.New("session authorization expired"))
		return
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-sess.done:
		return
	case <-timer.C:
		sess.terminateAuthorization(ctx, "expired", errors.New("session authorization expired"))
	}
}

func (sess *session) terminateAuthorization(ctx context.Context, reasonCode string, err error) {
	sess.authorizationTerminateOnce.Do(func() {
		sess.authorized.Store(false)
		sess.failAll(err)
		if reasonCode != "" {
			revokeCtx, revokeCancel := context.WithTimeout(ctx, sess.gateway.limits.WriteTimeout)
			_ = sess.sendControl(revokeCtx, 0, contractv1.SessionRevoked{
				ContractVersion: contractv1.ProtocolVersion,
				MessageType:     "session_revoked",
				AuthorizationID: sess.authorizationID,
				ReasonCode:      reasonCode,
			})
			revokeCancel()
		}
		if metadataTemporarilyUnavailable(err) {
			// Drop all authority and streams, but let the Agent reauthenticate
			// once a fresh snapshot is available. This is not a revocation.
			sess.close(websocket.StatusTryAgainLater, "authorization metadata unavailable")
			return
		}
		sess.close(websocket.StatusPolicyViolation, "authorization invalid")
	})
}

func (sess *session) revalidateAuthorization(ctx context.Context, now time.Time) (string, error) {
	if !now.Before(sess.authorizationExpiresAt) {
		return "expired", errors.New("session authorization expired")
	}

	record, err := sess.gateway.metadata.Authorization(ctx, sess.authorizationID, sess.deviceID, sess.tokenID, now)
	if err == nil {
		return "", nil
	}
	if record.AuthorizationID == sess.authorizationID && record.DeviceID == sess.deviceID && record.TokenID == sess.tokenID {
		if record.Disabled {
			return "disabled", fmt.Errorf("session authorization disabled: %w", err)
		}
		if expiresAt, parseErr := time.Parse(time.RFC3339, record.ExpiresAt); parseErr == nil && !now.Before(expiresAt) {
			return "expired", fmt.Errorf("session authorization expired: %w", err)
		}
	}
	for _, subject := range []struct{ kind, id string }{
		{"device_session_authorization", sess.authorizationID},
		{"device", sess.deviceID},
	} {
		if reasonSource, ok := sess.gateway.metadata.(interface {
			RevocationReason(context.Context, string, string, time.Time) (string, bool, error)
		}); ok {
			reason, revoked, revokeErr := reasonSource.RevocationReason(ctx, subject.kind, subject.id, now)
			if revokeErr != nil {
				return "", fmt.Errorf("authorization revocation lookup failed: %w", revokeErr)
			}
			if revoked {
				return sessionRevocationReason(reason), fmt.Errorf("session authorization revoked (%s): %w", reason, err)
			}
			continue
		}

		revoked, revokeErr := sess.gateway.metadata.Revoked(ctx, subject.kind, subject.id, now)
		if revokeErr != nil {
			return "", fmt.Errorf("authorization revocation lookup failed: %w", revokeErr)
		}
		if revoked {
			return "credential_revoked", fmt.Errorf("session authorization revoked: %w", err)
		}
	}
	return "", fmt.Errorf("session authorization invalid or unavailable: %w", err)
}

func sessionRevocationReason(reason string) string {
	switch reason {
	case "disabled", "credential_revoked", "security_hold", "expired":
		return reason
	default:
		return "credential_revoked"
	}
}
func (sess *session) handleControl(ctx context.Context, frame contractv1.Frame) error {
	if err := contractv1.ValidateControlPayload(frame.Payload, frame.StreamID, time.Now().UTC()); err != nil {
		// Malformed/unacceptable control payload data is close code 1007;
		// the remaining control violations are 1008 (section 11c).
		return closeViolation(websocket.StatusInvalidFramePayloadData, "invalid frame payload data", err)
	}
	var envelope struct {
		MessageType string `json:"message_type"`
	}
	if err := json.Unmarshal(frame.Payload, &envelope); err != nil {
		return err
	}

	switch envelope.MessageType {
	case "pong":
		var pong contractv1.Heartbeat
		if err := json.Unmarshal(frame.Payload, &pong); err != nil {
			return err
		}
		// Record the bounded heartbeat round-trip for aggregate latency
		// telemetry. Pair on the ping ID so only the matching pong updates
		// the observation; a missed or stale pong is ignored, leaving the
		// last observation in place.
		if armed, ok := sess.pendingPing.Load().(pendingPing); ok && armed.id != "" {
			if pong.PingID == armed.id {
				sess.pingLatency.Store(time.Since(armed.sentAt).Nanoseconds())
				sess.pendingPing.Store(pendingPing{})
			}
		}
		return nil
	case "health_report":
		var report contractv1.HealthReport
		if err := json.Unmarshal(frame.Payload, &report); err != nil {
			return err
		}
		// Health reports are bounded operational telemetry only: they
		// refresh liveness observation and are never authorization,
		// routing, or revocation authority. Validation already happened
		// in ValidateControlPayload above.
		sess.lastSeen.Store(time.Now().UnixNano())
		sess.gateway.resources.healthReports.Add(1)
		sess.gateway.logger.Debug("agent health report received",
			"device_id", sess.deviceID,
			"active_streams", report.ActiveStreams,
			"queued_frames", report.QueuedFrames,
			"reconnect_count", report.ReconnectCount)
		return nil
	case "ping":
		var ping contractv1.Heartbeat
		if err := json.Unmarshal(frame.Payload, &ping); err != nil {
			return err
		}
		return sess.sendControl(ctx, 0, contractv1.Heartbeat{
			ContractVersion: contractv1.ProtocolVersion,
			MessageType:     "pong",
			PingID:          ping.PingID,
			ReceivedAt:      time.Now().UTC().Format(time.RFC3339),
		})
	case "stream_close":
		sess.finishStream(frame.StreamID, io.EOF)
		return nil
	case "stream_error":
		var message contractv1.StreamError
		if err := json.Unmarshal(frame.Payload, &message); err != nil {
			return err
		}
		// Agent-controlled text is logged quoted: it may contain control
		// characters or log-forging sequences.
		sess.finishStream(frame.StreamID, fmt.Errorf("agent stream error %q: %q", message.Code, message.Message))
		return nil
	case "session_revoked":
		return errors.New("agent may not originate session_revoked")
	default:
		return fmt.Errorf("unexpected agent control message: %q", envelope.MessageType)
	}
}

func (sess *session) handleData(frame contractv1.Frame) error {
	sess.mu.Lock()
	stream := sess.streams[frame.StreamID]
	nextID := sess.nextID
	sess.mu.Unlock()
	if stream == nil {
		if frame.StreamID != 0 && frame.StreamID < nextID {
			sess.gateway.logger.Debug("dropping data for detached stream", "stream_id", frame.StreamID, "bytes", len(frame.Payload))
			return nil
		}
		return fmt.Errorf("data for unknown stream %d", frame.StreamID)
	}
	if err := stream.enqueue(frame.Payload); err != nil {
		sess.gateway.logger.Warn("stream enqueue rejected", "stream_id", frame.StreamID, "bytes", len(frame.Payload), "error", err)
		sess.errorStream(frame.StreamID, "resource_limit", "stream response queue exhausted", true, fmt.Errorf("stream %d inbound queue: %w", frame.StreamID, err))
		return nil
	}
	sess.gateway.resources.agentBytes.Add(uint64(len(frame.Payload)))
	return nil
}

func (sess *session) openStream(ctx context.Context, route contractv1.EndpointRouteAssignment) (*stream, error) {
	requestID, err := sess.gateway.newID("request")
	if err != nil {
		return nil, fmt.Errorf("generate request ID: %w", err)
	}
	sess.mu.Lock()
	if len(sess.streams) >= sess.gateway.limits.MaxStreamsPerSession {
		sess.mu.Unlock()
		return nil, errors.New("stream limit reached")
	}
	streamID := sess.nextID
	if streamID == 0 {
		sess.mu.Unlock()
		return nil, errors.New("stream ID exhausted")
	}
	sess.nextID++
	stream := newStream(
		ctx,
		streamID,
		sess.gateway.limits.MaxStreamQueueFrames,
		sess.gateway.limits.MaxStreamQueueBytes,
		sess.queueBudget,
		sess.gateway.resources.queueBytes,
		&sess.gateway.resources.queueRejects,
	)
	sess.streams[streamID] = stream
	sess.mu.Unlock()

	message := contractv1.StreamOpen{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "stream_open",
		EndpointID:      route.EndpointID,
		AssignmentID:    route.AssignmentID,
		LocalEndpointID: route.LocalEndpointID,
		RequestID:       requestID,
	}
	if err := sess.sendControl(ctx, streamID, message); err != nil {
		sess.finishStream(streamID, err)
		return nil, err
	}
	return stream, nil
}

func (sess *session) detachStream(streamID uint32, err error) *stream {
	sess.mu.Lock()
	stream := sess.streams[streamID]
	delete(sess.streams, streamID)
	sess.mu.Unlock()
	if stream != nil {
		stream.finish(err)
		stream.releaseQueuedChunks()
	}
	return stream
}

func (sess *session) closeStream(streamID uint32, reasonCode string) {
	if sess.detachStream(streamID, io.EOF) == nil {
		return
	}
	sess.gateway.logger.Debug("gateway closing stream", "stream_id", streamID, "reason", reasonCode)
	ctx, cancel := context.WithTimeout(context.Background(), sess.gateway.limits.WriteTimeout)
	defer cancel()
	_ = sess.sendControl(ctx, streamID, contractv1.StreamClose{ContractVersion: contractv1.ProtocolVersion, MessageType: "stream_close", ReasonCode: reasonCode})
}

func (sess *session) errorStream(streamID uint32, code, message string, retryable bool, streamErr error) {
	if sess.detachStream(streamID, streamErr) == nil {
		return
	}
	if len(message) > 256 {
		message = message[:256]
	}
	ctx, cancel := context.WithTimeout(context.Background(), sess.gateway.limits.WriteTimeout)
	defer cancel()
	_ = sess.sendControl(ctx, streamID, contractv1.StreamError{ContractVersion: contractv1.ProtocolVersion, MessageType: "stream_error", Code: code, Message: message, Retryable: retryable})
}

func (sess *session) finishStream(streamID uint32, err error) {
	_ = sess.detachStream(streamID, err)
}

func (sess *session) failAll(err error) {
	sess.mu.Lock()
	streams := sess.streams
	sess.streams = make(map[uint32]*stream)
	sess.mu.Unlock()
	for _, stream := range streams {
		stream.finish(err)
	}
}

func (sess *session) sendBytes(ctx context.Context, streamID uint32, payload []byte) error {
	for len(payload) > 0 {
		size := len(payload)
		if size > contractv1.MaxDataPayload {
			size = contractv1.MaxDataPayload
		}
		if err := sess.sendFrame(ctx, contractv1.KindData, streamID, payload[:size]); err != nil {
			return err
		}
		payload = payload[size:]
	}
	return nil
}

func (sess *session) sendControl(ctx context.Context, streamID uint32, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return sess.sendFrame(ctx, contractv1.KindControl, streamID, payload)
}

type sessionWriteRequest struct {
	ctx      context.Context
	kind     contractv1.Kind
	streamID uint32
	payload  []byte
	result   chan error
}

var errSessionWriterClosed = errors.New("gateway session writer closed")

func (sess *session) sendFrame(parent context.Context, kind contractv1.Kind, streamID uint32, payload []byte) error {
	ctx, cancel := context.WithTimeout(parent, sess.gateway.limits.WriteTimeout)
	defer cancel()
	request := sessionWriteRequest{ctx: ctx, kind: kind, streamID: streamID, payload: payload, result: make(chan error, 1)}
	queue := sess.dataWrites
	if kind == contractv1.KindControl {
		queue = sess.controlWrites
	}
	select {
	case queue <- request:
	case <-ctx.Done():
		return ctx.Err()
	case <-sess.done:
		return errSessionWriterClosed
	}
	if kind == contractv1.KindData {
		// Once accepted by the writer queue, data owns its place before the
		// caller can emit a terminal control frame. The writer applies its own
		// bounded deadline, so waiting here cannot silently reorder close/error
		// ahead of an accepted body chunk.
		select {
		case err := <-request.result:
			return err
		case <-sess.done:
			select {
			case err := <-request.result:
				return err
			default:
			}
			return errSessionWriterClosed
		}
	}
	select {
	case err := <-request.result:
		return err
	case <-ctx.Done():
		// Deadline fired: the write may still have completed concurrently.
		// Prefer a delivered result over the deadline error so a frame that
		// actually went out is never reported as failed (phantom-error
		// attribution makes callers tear down healthy tunnels).
		select {
		case err := <-request.result:
			return err
		default:
		}
		return ctx.Err()
	case <-sess.done:
		select {
		case err := <-request.result:
			return err
		default:
		}
		return errSessionWriterClosed
	}
}

func (sess *session) writeLoop() {
	var pendingData *sessionWriteRequest
	for {
		if pendingData != nil {
			select {
			case <-sess.done:
				return
			default:
			}
			// The held data frame goes out first: sustained control traffic
			// must never postpone the single in-flight tunneled-request
			// chunk past its write deadline (cross-queue order is free; only
			// per-stream ordering matters and that is sender-synchronized).
			request := *pendingData
			pendingData = nil
			sess.writeQueued(request)
			continue
		}

		select {
		case <-sess.done:
			return
		default:
		}
		select {
		case request := <-sess.controlWrites:
			sess.writeQueued(request)
			continue
		default:
		}
		select {
		case <-sess.done:
			return
		case request := <-sess.controlWrites:
			sess.writeQueued(request)
		case request := <-sess.dataWrites:
			pendingData = &request
		}
	}
}

func (sess *session) writeQueued(request sessionWriteRequest) {
	// Accepted tunnel data must never be dropped because its enqueue caller
	// timed out: doing so silently truncates the tunneled request body. Control
	// frames can still be abandoned when their caller no longer needs them.
	if err := request.ctx.Err(); err != nil && request.kind != contractv1.KindData {
		request.result <- err
		return
	}
	sequence, err := contractv1.NextSequence(sess.outbound.Load())
	if err != nil {
		sess.failAll(err)
		sess.close(websocket.StatusPolicyViolation, "sequence exhausted")
		request.result <- err
		return
	}
	frame, err := contractv1.EncodeFrame(contractv1.Frame{Kind: request.kind, StreamID: request.streamID, Sequence: sequence, Payload: request.payload})
	if err != nil {
		request.result <- err
		return
	}
	sess.outbound.Store(sequence)
	writeCtx := request.ctx
	if request.kind == contractv1.KindData {
		var cancel context.CancelFunc
		writeCtx, cancel = context.WithTimeout(context.Background(), sess.gateway.limits.WriteTimeout)
		defer cancel()
	}
	if err := sess.writeMessage(writeCtx, frame); err != nil {
		request.result <- err
		sess.failAll(err)
		sess.close(websocket.StatusInternalError, "protocol write failed")
		return
	}
	if request.kind == contractv1.KindData {
		sess.gateway.resources.publicBytes.Add(uint64(len(request.payload)))
	}
	request.result <- nil
}

func (sess *session) signalClosed() {
	sess.doneOnce.Do(func() { close(sess.done) })
}

// detachFromRouting removes the session from device routing synchronously at
// terminal-state time. The WebSocket close handshake can take the peer's whole
// close timeout (5 s by default), and leaving the session registered for that
// window would keep a dead session as the device's routing primary while a
// healthy standby tunnel is already available. unregisterSession is
// identity-checked, so a session that was already replaced (reconnect/resume)
// is left alone.
func (sess *session) detachFromRouting() {
	if sess.gateway == nil {
		return
	}
	sess.gateway.unregisterSession(sess)
}

func (sess *session) close(status websocket.StatusCode, reason string) {
	sess.signalClosed()
	sess.detachFromRouting()
	sess.closeOnce.Do(func() {
		if sess.closeConn != nil {
			_ = sess.closeConn(status, reason)
		}
	})
}

func (sess *session) forceClose() {
	sess.signalClosed()
	sess.detachFromRouting()
	sess.forceCloseOnce.Do(func() {
		if sess.closeNowConn != nil {
			_ = sess.closeNowConn()
		}
	})
}

type queuedPayload struct {
	data []byte
	size int64
}

type stream struct {
	id uint32
	// ctx is the ingressing request's context (plus the response-phase
	// inactivity deadline). Read selects on it so a tunnel read can never
	// outlive the request that owns the stream slot.
	ctx      context.Context
	incoming chan queuedPayload
	buffer   []byte
	queueMu  sync.Mutex
	closed   bool
	// terminalBuffer holds payload chunks that were still queued when the
	// terminal frame arrived; Read drains them before surfacing the
	// terminal error so close races can never truncate tunneled bodies.
	// terminalBytes is their reserved byte total: the reservation stays held
	// while the bytes are retained and is released exactly once, either on
	// dequeue in Read or when the abandoned tail is discarded.
	terminalBuffer []byte
	terminalBytes  int64
	terminalErr    error
	terminalReady  bool
	terminal       chan struct{}
	streamBudget   *byteBudget
	sessionBudget  *byteBudget
	globalBudget   *byteBudget
	rejectCounter  *atomic.Uint64
	finishOnce     sync.Once
}

func newStream(ctx context.Context, id uint32, queueFrames int, queueBytes int64, sessionBudget, globalBudget *byteBudget, rejectCounter *atomic.Uint64) *stream {
	return &stream{
		id:            id,
		ctx:           ctx,
		incoming:      make(chan queuedPayload, queueFrames),
		terminal:      make(chan struct{}),
		streamBudget:  newByteBudget(queueBytes),
		sessionBudget: sessionBudget,
		globalBudget:  globalBudget,
		rejectCounter: rejectCounter,
	}
}

func (stream *stream) enqueue(data []byte) error {
	size := int64(len(data))
	stream.queueMu.Lock()
	defer stream.queueMu.Unlock()
	if stream.closed {
		return errors.New("stream closed")
	}
	if !stream.streamBudget.TryAcquire(size) {
		stream.rejectCounter.Add(1)
		return errResourceBudget
	}
	if !stream.sessionBudget.TryAcquire(size) {
		stream.streamBudget.Release(size)
		stream.rejectCounter.Add(1)
		return errResourceBudget
	}
	if !stream.globalBudget.TryAcquire(size) {
		stream.sessionBudget.Release(size)
		stream.streamBudget.Release(size)
		stream.rejectCounter.Add(1)
		return errResourceBudget
	}
	payload := queuedPayload{data: append([]byte(nil), data...), size: size}
	select {
	case stream.incoming <- payload:
		return nil
	default:
		stream.releaseQueued(size)
		stream.rejectCounter.Add(1)
		return errors.New("frame queue full")
	}
}

func (stream *stream) releaseQueued(size int64) {
	stream.globalBudget.Release(size)
	stream.sessionBudget.Release(size)
	stream.streamBudget.Release(size)
}

func (stream *stream) Read(data []byte) (int, error) {
	for len(stream.buffer) == 0 {
		// Queued payload chunks are always drained first: a terminal frame
		// only means "no more data follows", so chunks racing the close
		// frame must still be delivered instead of truncating the body.
		select {
		case chunk := <-stream.incoming:
			stream.releaseQueued(chunk.size)
			stream.buffer = chunk.data
			continue
		default:
		}
		stream.queueMu.Lock()
		if stream.terminalReady {
			if len(stream.terminalBuffer) > 0 {
				tail := stream.terminalBuffer
				size := stream.terminalBytes
				stream.terminalBuffer = nil
				stream.terminalBytes = 0
				stream.queueMu.Unlock()
				stream.releaseQueued(size)
				stream.buffer = tail
				continue
			}
			err := stream.terminalErr
			stream.queueMu.Unlock()
			if err == nil {
				return 0, io.EOF
			}
			return 0, err
		}
		stream.queueMu.Unlock()
		select {
		case chunk := <-stream.incoming:
			stream.releaseQueued(chunk.size)
			stream.buffer = chunk.data
		case <-stream.terminal:
			// loop: the next pass drains terminalBuffer or returns the error
		case <-stream.ctx.Done():
			// The owning public request is gone (client cancellation) or the
			// response-phase inactivity deadline fired. Fail the read so the
			// ingress handler tears the stream down instead of holding its
			// global ingress slot for a stalled Agent.
			return 0, stream.ctx.Err()
		}
	}
	n := copy(data, stream.buffer)
	stream.buffer = stream.buffer[n:]
	return n, nil
}

func (stream *stream) finish(err error) {
	stream.finishOnce.Do(func() {
		stream.queueMu.Lock()
		stream.closed = true
		// Move still-queued chunks into the terminal buffer so Read can
		// deliver them before the terminal error: no-discard semantics. The
		// byte reservation stays held while the tail is retained and is
		// released on dequeue in Read (or when the tail is discarded), so
		// retained bytes are always accounted for.
		var tail []byte
		for {
			select {
			case chunk := <-stream.incoming:
				tail = append(tail, chunk.data...)
				continue
			default:
			}
			break
		}
		stream.terminalBuffer = tail
		stream.terminalBytes = int64(len(tail))
		stream.terminalErr = err
		stream.terminalReady = true
		stream.queueMu.Unlock()
		close(stream.terminal)
	})
}

// releaseQueuedChunks drains payload chunks left in the queue after the reader
// stopped (detached stream: client cancelled, handler returned) without
// touching the retained terminal tail, which a still-running reader may yet
// deliver. It keeps the shared byte budgets correct so abandoned streams
// cannot starve the session or global queues.
func (stream *stream) releaseQueuedChunks() {
	for {
		select {
		case chunk := <-stream.incoming:
			stream.releaseQueued(chunk.size)
		default:
			return
		}
	}
}

// discardRetained releases every byte this stream still holds, including a
// terminal tail the reader never drained. It must only be called once the
// reader has stopped, otherwise it would truncate a queued body.
func (stream *stream) discardRetained() {
	stream.releaseQueuedChunks()
	stream.queueMu.Lock()
	size := stream.terminalBytes
	stream.terminalBuffer = nil
	stream.terminalBytes = 0
	stream.queueMu.Unlock()
	if size > 0 {
		stream.releaseQueued(size)
	}
}
