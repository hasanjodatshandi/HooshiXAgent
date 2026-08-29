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

	writeMu                    sync.Mutex
	mu                         sync.Mutex
	streams                    map[uint32]*stream
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
		nextID:                 1,
		done:                   make(chan struct{}),
	}
	sess.outbound.Store(lastOutbound)
	sess.lastSeen.Store(time.Now().UnixNano())
	sess.authorized.Store(true)
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
	sess.mu.Unlock()
	if stream == nil {
		return fmt.Errorf("data for unknown stream %d", frame.StreamID)
	}
	payload := append([]byte(nil), frame.Payload...)
	select {
	case stream.incoming <- payload:
		return nil
	default:
		return fmt.Errorf("stream %d inbound queue full", frame.StreamID)
	}
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
	stream := newStream(streamID, sess.gateway.limits.MaxStreamQueueFrames)
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
		sess.removeStream(streamID)
		return nil, err
	}
	return stream, nil
}

func (sess *session) removeStream(streamID uint32) {
	sess.mu.Lock()
	stream := sess.streams[streamID]
	delete(sess.streams, streamID)
	sess.mu.Unlock()
	if stream != nil {
		stream.finish(io.EOF)
		ctx, cancel := context.WithTimeout(context.Background(), sess.gateway.limits.WriteTimeout)
		defer cancel()
		_ = sess.sendControl(ctx, streamID, contractv1.StreamClose{
			ContractVersion: contractv1.ProtocolVersion,
			MessageType:     "stream_close",
			ReasonCode:      "completed",
		})
	}
}

func (sess *session) finishStream(streamID uint32, err error) {
	sess.mu.Lock()
	stream := sess.streams[streamID]
	delete(sess.streams, streamID)
	sess.mu.Unlock()
	if stream != nil {
		stream.finish(err)
	}
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

func (sess *session) sendFrame(parent context.Context, kind contractv1.Kind, streamID uint32, payload []byte) error {
	ctx, cancel := context.WithTimeout(parent, sess.gateway.limits.WriteTimeout)
	defer cancel()

	sess.writeMu.Lock()
	defer sess.writeMu.Unlock()
	sequence, err := contractv1.NextSequence(sess.outbound.Load())
	if err != nil {
		sess.failAll(err)
		sess.close(websocket.StatusPolicyViolation, "sequence exhausted")
		return err
	}
	frame, err := contractv1.EncodeFrame(contractv1.Frame{Kind: kind, StreamID: streamID, Sequence: sequence, Payload: payload})
	if err != nil {
		return err
	}
	sess.outbound.Store(sequence)
	if err := sess.conn.Write(ctx, websocket.MessageBinary, frame); err != nil {
		sess.failAll(err)
		sess.close(websocket.StatusInternalError, "protocol write failed")
		return err
	}
	return nil
}

func (sess *session) close(status websocket.StatusCode, reason string) {
	sess.closeOnce.Do(func() {
		close(sess.done)
		if sess.conn != nil {
			_ = sess.conn.Close(status, reason)
		}
	})
}

type stream struct {
	id         uint32
	incoming   chan []byte
	errCh      chan error
	buffer     []byte
	finishOnce sync.Once
}

func newStream(id uint32, queueFrames int) *stream {
	return &stream{
		id:       id,
		incoming: make(chan []byte, queueFrames),
		errCh:    make(chan error, 1),
	}
}

func (stream *stream) Read(data []byte) (int, error) {
	for len(stream.buffer) == 0 {
		select {
		case chunk := <-stream.incoming:
			stream.buffer = chunk
			continue
		default:
		}
		select {
		case chunk := <-stream.incoming:
			stream.buffer = chunk
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
		stream.errCh <- err
	})
}
