package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

type agentSession struct {
	conn      *websocket.Conn
	config    Config
	limits    Limits
	logger    *slog.Logger
	sessionID string

	inbound  contractv1.SequenceTracker
	outbound atomic.Uint64
	writeMu  sync.Mutex

	mu          sync.Mutex
	streams     map[uint32]*agentStream
	maxStreamID uint32
	closed      chan struct{}
	closeOnce   sync.Once
}

type agentStream struct {
	id       uint32
	endpoint Endpoint
	incoming chan []byte
	ctx      context.Context
	cancel   context.CancelFunc
	finish   sync.Once
}

func authenticateAgent(
	parent context.Context,
	conn *websocket.Conn,
	config Config,
	privateKey ed25519.PrivateKey,
	token string,
	limits Limits,
	logger *slog.Logger,
) (*agentSession, error) {
	ctx, cancel := context.WithTimeout(parent, limits.HandshakeTimeout)
	defer cancel()

	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	hello := contractv1.ClientHello{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "client_hello",
		DeviceID:        config.DeviceID,
		AuthorizationID: config.AuthorizationID,
		TokenID:         config.TokenID,
		SessionToken:    token,
		ClientNonce:     nonce,
	}
	if err := writeInitialControl(ctx, conn, 1, hello); err != nil {
		return nil, err
	}

	var inbound contractv1.SequenceTracker
	challengeFrame, err := readAgentFrame(ctx, conn)
	if err != nil {
		return nil, err
	}
	if err := inbound.Accept(challengeFrame.Sequence); err != nil {
		return nil, err
	}
	if challengeFrame.Sequence != 1 || challengeFrame.Kind != contractv1.KindControl || challengeFrame.StreamID != 0 {
		return nil, errors.New("invalid server_challenge frame")
	}
	if err := contractv1.ValidateControlPayload(challengeFrame.Payload, 0, time.Now().UTC()); err != nil {
		return nil, err
	}
	challenge, err := contractv1.DecodeServerChallenge(challengeFrame.Payload)
	if err != nil {
		return nil, err
	}

	signature := ed25519.Sign(privateKey, contractv1.AuthTranscript(hello, challenge))
	auth := contractv1.ClientAuth{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "client_auth",
		SessionID:       challenge.SessionID,
		Signature:       base64.RawURLEncoding.EncodeToString(signature),
	}
	if err := writeInitialControl(ctx, conn, 2, auth); err != nil {
		return nil, err
	}

	readyFrame, err := readAgentFrame(ctx, conn)
	if err != nil {
		return nil, err
	}
	if err := inbound.Accept(readyFrame.Sequence); err != nil {
		return nil, err
	}
	if readyFrame.Sequence != 2 || readyFrame.Kind != contractv1.KindControl || readyFrame.StreamID != 0 {
		return nil, errors.New("invalid session_ready frame")
	}
	if err := contractv1.ValidateControlPayload(readyFrame.Payload, 0, time.Now().UTC()); err != nil {
		return nil, err
	}
	var ready contractv1.SessionReady
	if err := json.Unmarshal(readyFrame.Payload, &ready); err != nil {
		return nil, err
	}
	if ready.SessionID != challenge.SessionID {
		return nil, errors.New("session_ready session ID mismatch")
	}

	sess := &agentSession{
		conn:      conn,
		config:    config,
		limits:    limits,
		logger:    logger,
		sessionID: ready.SessionID,
		inbound:   inbound,
		streams:   make(map[uint32]*agentStream),
		closed:    make(chan struct{}),
	}
	sess.outbound.Store(2)
	sess.limits.IdleTimeout = time.Duration(ready.IdleTimeoutSeconds) * time.Second
	return sess, nil
}

func (sess *agentSession) run(parent context.Context) error {
	defer sess.shutdown()
	idle := sess.limits.IdleTimeout
	for {
		readCtx, cancel := context.WithTimeout(parent, idle)
		frame, err := readAgentFrame(readCtx, sess.conn)
		cancel()
		if err != nil {
			if parent.Err() != nil {
				return parent.Err()
			}
			return err
		}
		if err := sess.inbound.Accept(frame.Sequence); err != nil {
			return err
		}
		switch frame.Kind {
		case contractv1.KindControl:
			if err := sess.handleControl(parent, frame); err != nil {
				return err
			}
		case contractv1.KindData:
			if err := sess.handleData(frame); err != nil {
				return err
			}
		default:
			return errors.New("unknown protocol frame kind")
		}
	}
}

func (sess *agentSession) handleControl(parent context.Context, frame contractv1.Frame) error {
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
	case "ping":
		var ping contractv1.Heartbeat
		if err := json.Unmarshal(frame.Payload, &ping); err != nil {
			return err
		}
		return sess.sendControl(parent, 0, contractv1.Heartbeat{
			ContractVersion: contractv1.ProtocolVersion,
			MessageType:     "pong",
			PingID:          ping.PingID,
			ReceivedAt:      time.Now().UTC().Format(time.RFC3339),
		})
	case "pong":
		return nil
	case "session_revoked":
		return ErrSessionRevoked
	case "stream_open":
		return sess.handleStreamOpen(parent, frame)
	case "stream_close":
		sess.finishStream(frame.StreamID)
		return nil
	case "stream_error":
		sess.finishStream(frame.StreamID)
		return nil
	default:
		return fmt.Errorf("unexpected Gateway control message %q", envelope.MessageType)
	}
}

func (sess *agentSession) handleStreamOpen(parent context.Context, frame contractv1.Frame) error {
	var message contractv1.StreamOpen
	if err := json.Unmarshal(frame.Payload, &message); err != nil {
		return err
	}
	if frame.StreamID == 0 {
		return errors.New("stream_open requires non-zero stream ID")
	}

	sess.mu.Lock()
	if frame.StreamID <= sess.maxStreamID {
		sess.mu.Unlock()
		return fmt.Errorf("stream ID reused or out of order: %d", frame.StreamID)
	}
	sess.maxStreamID = frame.StreamID
	if len(sess.streams) >= sess.limits.MaxStreams {
		sess.mu.Unlock()
		return sess.sendStreamError(parent, frame.StreamID, "resource_limit", "active stream limit reached", true)
	}
	endpoint, ok := sess.config.EndpointByID(message.LocalEndpointID)
	if !ok {
		sess.mu.Unlock()
		return sess.sendStreamError(parent, frame.StreamID, "route_revoked", "local endpoint is not configured", false)
	}
	streamCtx, cancel := context.WithCancel(parent)
	stream := &agentStream{
		id:       frame.StreamID,
		endpoint: endpoint,
		incoming: make(chan []byte, sess.limits.MaxQueueFrames),
		ctx:      streamCtx,
		cancel:   cancel,
	}
	sess.streams[frame.StreamID] = stream
	sess.mu.Unlock()

	go sess.serveStream(stream)
	return nil
}

func (sess *agentSession) handleData(frame contractv1.Frame) error {
	sess.mu.Lock()
	stream := sess.streams[frame.StreamID]
	sess.mu.Unlock()
	if stream == nil {
		return fmt.Errorf("data received for unknown stream %d", frame.StreamID)
	}
	payload := append([]byte(nil), frame.Payload...)
	select {
	case stream.incoming <- payload:
		return nil
	default:
		_ = sess.sendStreamError(context.Background(), frame.StreamID, "resource_limit", "stream input queue is full", true)
		sess.finishStream(frame.StreamID)
		return nil
	}
}

func (sess *agentSession) serveStream(stream *agentStream) {
	conn, err := DialLocalTarget(stream.ctx, stream.endpoint.Target, sess.limits.DialTimeout)
	if err != nil {
		_ = sess.sendStreamError(context.Background(), stream.id, "local_target_unavailable", "approved local target is unavailable", true)
		sess.finishStream(stream.id)
		return
	}
	defer conn.Close()
	go func() {
		<-stream.ctx.Done()
		_ = conn.Close()
	}()

	writerDone := make(chan error, 1)
	go func() { writerDone <- sess.writeLocal(stream, conn) }()

	buffer := make([]byte, 32*1024)
readLoop:
	for {
		if err := conn.SetReadDeadline(time.Now().Add(sess.limits.IdleTimeout)); err != nil {
			break
		}
		n, readErr := conn.Read(buffer)
		if n > 0 {
			if err := sess.sendBytes(stream.ctx, stream.id, buffer[:n]); err != nil {
				break
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				sess.logger.Debug("local stream read ended", "stream_id", stream.id, "error", readErr)
			}
			break
		}
		select {
		case <-stream.ctx.Done():
			break readLoop
		default:
		}
	}
	peerClosed := stream.ctx.Err() != nil
	stream.cancel()
	_ = conn.Close()
	select {
	case <-writerDone:
	case <-time.After(sess.limits.WriteTimeout):
	}
	if !peerClosed {
		_ = sess.sendControl(context.Background(), stream.id, contractv1.StreamClose{
			ContractVersion: contractv1.ProtocolVersion,
			MessageType:     "stream_close",
			ReasonCode:      "completed",
		})
	}
	sess.finishStream(stream.id)
}

func (sess *agentSession) writeLocal(stream *agentStream, conn net.Conn) error {
	for {
		select {
		case <-stream.ctx.Done():
			return nil
		case payload := <-stream.incoming:
			if err := conn.SetWriteDeadline(time.Now().Add(sess.limits.WriteTimeout)); err != nil {
				return err
			}
			for len(payload) > 0 {
				n, err := conn.Write(payload)
				if err != nil {
					return err
				}
				payload = payload[n:]
			}
		}
	}
}

func (sess *agentSession) sendBytes(parent context.Context, streamID uint32, payload []byte) error {
	for len(payload) > 0 {
		size := len(payload)
		if size > contractv1.MaxDataPayload {
			size = contractv1.MaxDataPayload
		}
		if err := sess.sendFrame(parent, contractv1.KindData, streamID, payload[:size]); err != nil {
			return err
		}
		payload = payload[size:]
	}
	return nil
}

func (sess *agentSession) sendControl(parent context.Context, streamID uint32, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return sess.sendFrame(parent, contractv1.KindControl, streamID, payload)
}

func (sess *agentSession) sendStreamError(parent context.Context, streamID uint32, code, message string, retryable bool) error {
	if len(message) > 256 {
		message = message[:256]
	}
	return sess.sendControl(parent, streamID, contractv1.StreamError{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "stream_error",
		Code:            code,
		Message:         message,
		Retryable:       retryable,
	})
}

func (sess *agentSession) sendFrame(parent context.Context, kind contractv1.Kind, streamID uint32, payload []byte) error {
	ctx, cancel := context.WithTimeout(parent, sess.limits.WriteTimeout)
	defer cancel()
	sess.writeMu.Lock()
	defer sess.writeMu.Unlock()
	sequence := sess.outbound.Add(1)
	encoded, err := contractv1.EncodeFrame(contractv1.Frame{
		Kind:     kind,
		StreamID: streamID,
		Sequence: sequence,
		Payload:  payload,
	})
	if err != nil {
		return err
	}
	return sess.conn.Write(ctx, websocket.MessageBinary, encoded)
}

func (sess *agentSession) finishStream(streamID uint32) {
	sess.mu.Lock()
	stream := sess.streams[streamID]
	delete(sess.streams, streamID)
	sess.mu.Unlock()
	if stream != nil {
		stream.finish.Do(stream.cancel)
	}
}

func (sess *agentSession) shutdown() {
	sess.closeOnce.Do(func() {
		close(sess.closed)
		sess.mu.Lock()
		streams := sess.streams
		sess.streams = make(map[uint32]*agentStream)
		sess.mu.Unlock()
		for _, stream := range streams {
			stream.finish.Do(stream.cancel)
		}
		sess.conn.CloseNow()
	})
}

func readAgentFrame(ctx context.Context, conn *websocket.Conn) (contractv1.Frame, error) {
	messageType, payload, err := conn.Read(ctx)
	if err != nil {
		return contractv1.Frame{}, err
	}
	if messageType != websocket.MessageBinary {
		return contractv1.Frame{}, errors.New("protocol requires binary WebSocket messages")
	}
	return contractv1.DecodeFrame(payload)
}

func writeInitialControl(ctx context.Context, conn *websocket.Conn, sequence uint64, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded, err := contractv1.EncodeFrame(contractv1.Frame{
		Kind:     contractv1.KindControl,
		StreamID: 0,
		Sequence: sequence,
		Payload:  payload,
	})
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageBinary, encoded)
}

func randomNonce() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate client nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
