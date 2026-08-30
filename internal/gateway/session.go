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

	controlWrites              chan sessionWriteRequest
	dataWrites                 chan sessionWriteRequest
	writeMessage               func(context.Context, []byte) error
	mu                         sync.Mutex
	streams                    map[uint32]*stream
	queueBudget                *byteBudget
	nextID                     uint32
	done                       chan struct{}
	closeOnce                  sync.Once
	authorizationTerminateOnce sync.Once
}

func newSession(gateway *Gateway, conn *websocket.Conn, deviceID, sessionID, authorizationID, tokenID string, authorizationExpiresAt time.Time, inbound contractv1.SequenceTracker, lastOutbound uint64) *session {
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
	sess.outbound.Store(lastOutbound)
	sess.lastSeen.Store(time.Now().UnixNano())
	sess.authorized.Store(true)
	go sess.writeLoop()
	return sess
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
			sess.close(websocket.StatusNormalClosure, "session ended")
			return
		}
		if err := sess.inbound.Accept(frame.Sequence); err != nil {
			sess.failAll(err)
			sess.close(websocket.StatusPolicyViolation, "sequence violation")
			return
		}
		sess.lastSeen.Store(time.Now().UnixNano())

		switch frame.Kind {
		case contractv1.KindControl:
			if err := sess.handleControl(ctx, frame); err != nil {
				sess.failAll(err)
				sess.close(websocket.StatusPolicyViolation, "control violation")
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
			sess.close(websocket.StatusPolicyViolation, "unknown frame kind")
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
			ping := contractv1.Heartbeat{
				ContractVersion: contractv1.ProtocolVersion,
				MessageType:     "ping",
				PingID:          newID("ping"),
				SentAt:          time.Now().UTC().Format(time.RFC3339),
			}
			pingCtx, cancel := context.WithTimeout(ctx, sess.gateway.limits.WriteTimeout)
			err := sess.sendControl(pingCtx, 0, ping)
			cancel()
			if err != nil {
				sess.failAll(err)
				sess.close(websocket.StatusInternalError, "heartbeat write failed")
				return
			}
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
		revoked, revokeErr := sess.gateway.metadata.Revoked(ctx, subject.kind, subject.id, now)
		if revokeErr != nil {
			return "", fmt.Errorf("authorization revalidation failed: %w", err)
		}
		if revoked {
			return "credential_revoked", fmt.Errorf("session authorization revoked: %w", err)
		}
	}
	return "", fmt.Errorf("session authorization invalid or unavailable: %w", err)
}
func (sess *session) handleControl(ctx context.Context, frame contractv1.Frame) error {
	if err := contractv1.ValidateControlPayload(frame.Payload, frame.StreamID, time.Now().UTC()); err != nil {
		return err
	}
	var envelope struct {
		MessageType string `json:"message_type"`
	}
	if err := json.Unmarshal(frame.Payload, &envelope); err != nil {
		return err
	}

	switch envelope.MessageType {
	case "pong":
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
		sess.finishStream(frame.StreamID, fmt.Errorf("agent stream error %s: %s", message.Code, message.Message))
		return nil
	case "session_revoked":
		return errors.New("agent may not originate session_revoked")
	default:
		return fmt.Errorf("unexpected agent control message: %s", envelope.MessageType)
	}
}

func (sess *session) handleData(frame contractv1.Frame) error {
	sess.mu.Lock()
	stream := sess.streams[frame.StreamID]
	nextID := sess.nextID
	sess.mu.Unlock()
	if stream == nil {
		if frame.StreamID != 0 && frame.StreamID < nextID {
			return nil
		}
		return fmt.Errorf("data for unknown stream %d", frame.StreamID)
	}
	if err := stream.enqueue(frame.Payload); err != nil {
		sess.errorStream(frame.StreamID, "resource_limit", "stream response queue exhausted", true, fmt.Errorf("stream %d inbound queue: %w", frame.StreamID, err))
		return nil
	}
	return nil
}

func (sess *session) openStream(ctx context.Context, route contractv1.EndpointRouteAssignment) (*stream, error) {
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
		RequestID:       newID("request"),
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
	}
	return stream
}

func (sess *session) closeStream(streamID uint32, reasonCode string) {
	if sess.detachStream(streamID, io.EOF) == nil {
		return
	}
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
	select {
	case err := <-request.result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-sess.done:
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
			select {
			case request := <-sess.controlWrites:
				sess.writeQueued(request)
				continue
			default:
			}
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
	if err := request.ctx.Err(); err != nil {
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
	if err := sess.writeMessage(request.ctx, frame); err != nil {
		request.result <- err
		sess.failAll(err)
		sess.close(websocket.StatusInternalError, "protocol write failed")
		return
	}
	request.result <- nil
}

func (sess *session) close(status websocket.StatusCode, reason string) {
	sess.closeOnce.Do(func() {
		close(sess.done)
		if sess.conn != nil {
			_ = sess.conn.Close(status, reason)
		}
	})
}

type queuedPayload struct {
	data []byte
	size int64
}

type stream struct {
	id            uint32
	incoming      chan queuedPayload
	errCh         chan error
	buffer        []byte
	queueMu       sync.Mutex
	closed        bool
	streamBudget  *byteBudget
	sessionBudget *byteBudget
	globalBudget  *byteBudget
	rejectCounter *atomic.Uint64
	finishOnce    sync.Once
}

func newStream(id uint32, queueFrames int, queueBytes int64, sessionBudget, globalBudget *byteBudget, rejectCounter *atomic.Uint64) *stream {
	return &stream{
		id:            id,
		incoming:      make(chan queuedPayload, queueFrames),
		errCh:         make(chan error, 1),
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
	if !stream.streamBudget.tryAcquire(size) {
		stream.rejectCounter.Add(1)
		return errResourceBudget
	}
	if !stream.sessionBudget.tryAcquire(size) {
		stream.streamBudget.release(size)
		stream.rejectCounter.Add(1)
		return errResourceBudget
	}
	if !stream.globalBudget.tryAcquire(size) {
		stream.sessionBudget.release(size)
		stream.streamBudget.release(size)
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
	stream.globalBudget.release(size)
	stream.sessionBudget.release(size)
	stream.streamBudget.release(size)
}

func (stream *stream) Read(data []byte) (int, error) {
	for len(stream.buffer) == 0 {
		select {
		case chunk := <-stream.incoming:
			stream.releaseQueued(chunk.size)
			stream.buffer = chunk.data
			continue
		default:
		}
		select {
		case chunk := <-stream.incoming:
			stream.releaseQueued(chunk.size)
			stream.buffer = chunk.data
		case err := <-stream.errCh:
			if err == nil {
				return 0, io.EOF
			}
			return 0, err
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
		for {
			select {
			case chunk := <-stream.incoming:
				stream.releaseQueued(chunk.size)
			default:
				stream.queueMu.Unlock()
				stream.errCh <- err
				return
			}
		}
	})
}
