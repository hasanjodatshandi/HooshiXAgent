package gateway

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

const agentPath = "/agent/v1/connect"

type Gateway struct {
	metadata MetadataSource
	status   *statusExporter
	limits   Limits
	logger   *slog.Logger

	mu             sync.RWMutex
	sessions       map[string]*session
	handshakeSlots chan struct{}
	resources      gatewayResources
}

func New(metadata MetadataSource, status StatusSink, limits Limits, logger *slog.Logger) (*Gateway, error) {
	if metadata == nil {
		return nil, errors.New("metadata source is required")
	}
	if status == nil {
		status = NopStatusSink{}
	}
	if !limits.valid() {
		return nil, errors.New("invalid gateway limits")
	}
	if logger == nil {
		logger = slog.Default()
	}
	gateway := &Gateway{
		metadata:       metadata,
		limits:         limits,
		logger:         logger,
		sessions:       make(map[string]*session),
		handshakeSlots: make(chan struct{}, limits.MaxPendingHandshakes),
		resources:      newGatewayResources(limits),
	}
	gateway.status = newStatusExporter(status, logger, limits.MaxStatusQueueSignals, limits.StatusEmitTimeout)
	return gateway, nil
}

func (gateway *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", gateway.handleHealth)
	mux.HandleFunc("GET /readyz", gateway.handleReady)
	mux.HandleFunc("GET /metrics", gateway.handleMetrics)
	mux.HandleFunc(agentPath, gateway.handleAgent)
	mux.HandleFunc("/", gateway.handleIngress)
	return mux
}

func (gateway *Gateway) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

func (gateway *Gateway) handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if readiness, ok := gateway.metadata.(interface{ Ready() error }); ok {
		if err := readiness.Ready(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"status":"not_ready"}`)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"status":"ready"}`)
}

func (gateway *Gateway) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	gateway.mu.RLock()
	sessions := make([]*session, 0, len(gateway.sessions))
	for _, sess := range gateway.sessions {
		sessions = append(sessions, sess)
	}
	gateway.mu.RUnlock()

	activeStreams := 0
	for _, sess := range sessions {
		sess.mu.Lock()
		activeStreams += len(sess.streams)
		sess.mu.Unlock()
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_agent_sessions Current authenticated Agent sessions.\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_agent_sessions gauge\n")
	_, _ = fmt.Fprintf(w, "hooshix_gateway_agent_sessions %d\n", len(sessions))
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_agent_sessions_limit gauge\n")
	_, _ = fmt.Fprintf(w, "hooshix_gateway_agent_sessions_limit %d\n", gateway.limits.MaxAgentSessions)
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_active_streams Current active tunnel streams.\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_active_streams gauge\n")
	_, _ = fmt.Fprintf(w, "hooshix_gateway_active_streams %d\n", activeStreams)
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_pending_handshakes Current Agent handshakes consuming bounded slots.\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_pending_handshakes gauge\n")
	_, _ = fmt.Fprintf(w, "hooshix_gateway_pending_handshakes %d\n", len(gateway.handshakeSlots))
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_pending_handshakes_limit gauge\n")
	_, _ = fmt.Fprintf(w, "hooshix_gateway_pending_handshakes_limit %d\n", gateway.limits.MaxPendingHandshakes)

	queueUsed, queueLimit, _ := gateway.resources.queueBytes.snapshot()
	ingressUsed, ingressLimit, _ := gateway.resources.ingressBytes.snapshot()
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_queued_bytes Current Agent-to-Gateway payload bytes waiting in stream queues.\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_queued_bytes gauge\n")
	_, _ = fmt.Fprintf(w, "hooshix_gateway_queued_bytes %d\n", queueUsed)
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_queued_bytes_limit Global queued-payload byte budget.\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_queued_bytes_limit gauge\n")
	_, _ = fmt.Fprintf(w, "hooshix_gateway_queued_bytes_limit %d\n", queueLimit)
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_ingress_inflight Current public ingress requests consuming bounded slots.\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_ingress_inflight gauge\n")
	_, _ = fmt.Fprintf(w, "hooshix_gateway_ingress_inflight %d\n", len(gateway.resources.ingressSlots))
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_ingress_inflight_limit gauge\n")
	_, _ = fmt.Fprintf(w, "hooshix_gateway_ingress_inflight_limit %d\n", gateway.limits.MaxIngressInFlight)
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_ingress_inflight_bytes Current public-ingress bytes reserved while bounded tunnel chunks are being forwarded.\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_ingress_inflight_bytes gauge\n")
	_, _ = fmt.Fprintf(w, "hooshix_gateway_ingress_inflight_bytes %d\n", ingressUsed)
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_ingress_inflight_bytes_limit Global public-ingress streaming chunk byte budget.\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_ingress_inflight_bytes_limit gauge\n")
	_, _ = fmt.Fprintf(w, "hooshix_gateway_ingress_inflight_bytes_limit %d\n", ingressLimit)
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_queue_rejections_total counter\nhooshix_gateway_queue_rejections_total %d\n", gateway.resources.queueRejects.Load())
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_handshake_rejections_total counter\nhooshix_gateway_handshake_rejections_total %d\n", gateway.resources.handshakeRejects.Load()+gateway.resources.handshakeRate.rejected.Load())
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_ingress_rejections_total counter\nhooshix_gateway_ingress_rejections_total %d\n", gateway.resources.ingressRejects.Load()+gateway.resources.ingressRate.rejected.Load())
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_session_capacity_rejections_total counter\nhooshix_gateway_session_capacity_rejections_total %d\n", gateway.resources.sessionRejects.Load())
	statusQueued, statusLimit, statusDropped, statusFailures := gateway.status.snapshot()
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_status_queue_depth Current queued status signals waiting for asynchronous export.\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_status_queue_depth gauge\nhooshix_gateway_status_queue_depth %d\n", statusQueued)
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_status_queue_limit gauge\nhooshix_gateway_status_queue_limit %d\n", statusLimit)
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_status_dropped_total counter\nhooshix_gateway_status_dropped_total %d\n", statusDropped)
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_status_export_failures_total counter\nhooshix_gateway_status_export_failures_total %d\n", statusFailures)
}

func (gateway *Gateway) handleAgent(w http.ResponseWriter, request *http.Request) {
	if !gateway.resources.handshakeRate.allow(time.Now()) {
		http.Error(w, "agent handshake rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	select {
	case gateway.handshakeSlots <- struct{}{}:
	default:
		gateway.resources.handshakeRejects.Add(1)
		http.Error(w, "too many pending handshakes", http.StatusServiceUnavailable)
		return
	}
	handshakeSlotHeld := true
	releaseHandshakeSlot := func() {
		if handshakeSlotHeld {
			<-gateway.handshakeSlots
			handshakeSlotHeld = false
		}
	}
	defer releaseHandshakeSlot()

	conn, err := websocket.Accept(w, request, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		gateway.logger.Warn("agent websocket accept failed", "error", err)
		return
	}
	conn.SetReadLimit(contractv1.HeaderSize + contractv1.MaxDataPayload)

	ctx, cancel := context.WithTimeout(request.Context(), gateway.limits.HandshakeTimeout)
	sess, err := gateway.authenticate(ctx, conn)
	cancel()
	releaseHandshakeSlot()
	if err != nil {
		gateway.logger.Warn("agent authentication failed", "error", err)
		_ = conn.Close(websocket.StatusPolicyViolation, "authentication failed")
		return
	}

	if err := gateway.registerSession(sess); err != nil {
		_ = conn.Close(websocket.StatusTryAgainLater, "session capacity reached")
		return
	}
	defer gateway.unregisterSession(sess)

	gateway.emitStatus(context.Background(), contractv1.GatewayStatusSignal{
		ContractVersion: contractv1.ProtocolVersion,
		EventID:         newID("status"),
		ObservedAt:      time.Now().UTC().Format(time.RFC3339),
		Kind:            "session_connected",
		DeviceID:        sess.deviceID,
		SessionID:       sess.sessionID,
	})

	gateway.logger.Info("agent session authenticated", "device_id", sess.deviceID, "session_id", sess.sessionID)
	sess.run(request.Context())

	gateway.emitStatus(context.Background(), contractv1.GatewayStatusSignal{
		ContractVersion: contractv1.ProtocolVersion,
		EventID:         newID("status"),
		ObservedAt:      time.Now().UTC().Format(time.RFC3339),
		Kind:            "session_disconnected",
		DeviceID:        sess.deviceID,
		SessionID:       sess.sessionID,
	})
}

func (gateway *Gateway) authenticate(ctx context.Context, conn *websocket.Conn) (*session, error) {
	var inbound contractv1.SequenceTracker

	first, err := readProtocolFrame(ctx, conn)
	if err != nil {
		return nil, err
	}
	if err := inbound.Accept(first.Sequence); err != nil {
		return nil, err
	}
	if first.Kind != contractv1.KindControl || first.StreamID != 0 {
		return nil, errors.New("first frame must be session control")
	}
	if err := contractv1.ValidateControlPayload(first.Payload, 0, time.Now().UTC()); err != nil {
		return nil, err
	}
	hello, err := contractv1.DecodeClientHello(first.Payload)
	if err != nil {
		return nil, err
	}

	record, err := gateway.metadata.Authorization(ctx, hello.AuthorizationID, hello.DeviceID, hello.TokenID, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("authorization lookup: %w", err)
	}
	if !contractv1.MatchSessionToken(record, hello.SessionToken) {
		return nil, errors.New("session token mismatch")
	}

	challenge := contractv1.ServerChallenge{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "server_challenge",
		SessionID:       newID("session"),
		ServerNonce:     randomBase64URL(32),
		ExpiresAt:       time.Now().UTC().Add(gateway.limits.HandshakeTimeout).Format(time.RFC3339),
	}
	if err := writeControlFrame(ctx, conn, 1, 0, challenge); err != nil {
		return nil, err
	}

	second, err := readProtocolFrame(ctx, conn)
	if err != nil {
		return nil, err
	}
	if err := inbound.Accept(second.Sequence); err != nil {
		return nil, err
	}
	if second.Kind != contractv1.KindControl || second.StreamID != 0 {
		return nil, errors.New("client_auth must be session control")
	}
	if err := contractv1.ValidateControlPayload(second.Payload, 0, time.Now().UTC()); err != nil {
		return nil, err
	}
	auth, err := contractv1.DecodeClientAuth(second.Payload)
	if err != nil {
		return nil, err
	}
	if err := contractv1.VerifyClientAuthSignature(record.DevicePublicKey, hello, challenge, auth); err != nil {
		return nil, err
	}
	authorizationExpiresAt, err := time.Parse(time.RFC3339, record.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse authorization expiry: %w", err)
	}

	ready := contractv1.SessionReady{
		ContractVersion:          contractv1.ProtocolVersion,
		MessageType:              "session_ready",
		SessionID:                challenge.SessionID,
		HeartbeatIntervalSeconds: int(gateway.limits.HeartbeatInterval / time.Second),
		IdleTimeoutSeconds:       int(gateway.limits.IdleTimeout / time.Second),
	}
	if err := writeControlFrame(ctx, conn, 2, 0, ready); err != nil {
		return nil, err
	}

	return newSession(gateway, conn, record.DeviceID, challenge.SessionID, record.AuthorizationID, record.TokenID, authorizationExpiresAt, inbound, 2), nil
}

func (gateway *Gateway) registerSession(sess *session) error {
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	if current, ok := gateway.sessions[sess.deviceID]; ok {
		current.close(websocket.StatusNormalClosure, "replaced by reconnect")
		delete(gateway.sessions, sess.deviceID)
	}
	if len(gateway.sessions) >= gateway.limits.MaxAgentSessions {
		gateway.resources.sessionRejects.Add(1)
		return errors.New("agent session capacity reached")
	}
	gateway.sessions[sess.deviceID] = sess
	return nil
}

func (gateway *Gateway) unregisterSession(sess *session) {
	gateway.mu.Lock()
	defer gateway.mu.Unlock()
	if current, ok := gateway.sessions[sess.deviceID]; ok && current == sess {
		delete(gateway.sessions, sess.deviceID)
	}
}

func (gateway *Gateway) sessionForDevice(deviceID string) *session {
	gateway.mu.RLock()
	sess := gateway.sessions[deviceID]
	gateway.mu.RUnlock()
	if sess == nil || !sess.authorized.Load() {
		return nil
	}
	if !sess.authorizationExpiresAt.IsZero() && !time.Now().UTC().Before(sess.authorizationExpiresAt) {
		return nil
	}
	return sess
}

func (gateway *Gateway) handleIngress(w http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/healthz" || request.URL.Path == "/readyz" || request.URL.Path == "/metrics" || request.URL.Path == agentPath {
		http.NotFound(w, request)
		return
	}
	if request.ContentLength > gateway.limits.MaxRequestBytes {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	if !gateway.resources.ingressRate.allow(time.Now()) {
		http.Error(w, "public ingress rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	select {
	case gateway.resources.ingressSlots <- struct{}{}:
		defer func() { <-gateway.resources.ingressSlots }()
	default:
		gateway.resources.ingressRejects.Add(1)
		http.Error(w, "public ingress capacity reached", http.StatusServiceUnavailable)
		return
	}

	now := time.Now().UTC()
	route, err := gateway.metadata.RouteByHostname(request.Context(), request.Host, now)
	if err != nil {
		http.Error(w, "route not found", http.StatusNotFound)
		return
	}
	sess := gateway.sessionForDevice(route.DeviceID)
	if sess == nil {
		http.Error(w, "agent offline", http.StatusServiceUnavailable)
		return
	}

	stream, err := sess.openStream(request.Context(), route)
	if err != nil {
		http.Error(w, "stream unavailable", http.StatusServiceUnavailable)
		return
	}
	terminalReason := "cancelled"
	terminalCode := ""
	terminalMessage := ""
	terminalRetryable := false
	defer func() {
		if terminalCode != "" {
			sess.errorStream(stream.id, terminalCode, terminalMessage, terminalRetryable, errors.New(terminalMessage))
			return
		}
		sess.closeStream(stream.id, terminalReason)
	}()

	tunnelRequest := cloneRequestForTunnel(request)
	tunnelRequest.Body = http.MaxBytesReader(w, request.Body, gateway.limits.MaxRequestBytes)
	streamWriter := newRequestStreamWriter(request.Context(), gateway.resources.ingressBytes, &gateway.resources.ingressRejects, func(ctx context.Context, payload []byte) error {
		return sess.sendBytes(ctx, stream.id, payload)
	})
	limited := &limitWriter{w: streamWriter, remaining: gateway.limits.MaxRequestBytes + int64(gateway.limits.MaxHeaderBytes)}
	if err := tunnelRequest.Write(limited); err != nil {
		if errors.Is(err, errResourceBudget) {
			terminalCode, terminalMessage, terminalRetryable = "resource_limit", "public ingress byte budget exhausted", true
			http.Error(w, terminalMessage, http.StatusServiceUnavailable)
			return
		}
		if request.Context().Err() != nil {
			return
		}
		terminalCode, terminalMessage = "protocol_error", "request serialization failed"
		http.Error(w, terminalMessage, http.StatusBadRequest)
		return
	}
	fromPublic := streamWriter.Written()

	headerLimited := newResponseHeaderLimitReader(stream, int64(gateway.limits.MaxHeaderBytes))
	response, err := http.ReadResponse(bufio.NewReader(headerLimited), tunnelRequest)
	if err != nil {
		terminalCode, terminalMessage = "protocol_error", "invalid tunneled response"
		if errors.Is(err, errResponseHeaderTooLarge) {
			terminalCode, terminalMessage = "resource_limit", "tunneled response headers too large"
		}
		gateway.logger.Warn(terminalMessage, "error", err, "endpoint_id", route.EndpointID, "stream_id", stream.id)
		http.Error(w, terminalMessage, http.StatusBadGateway)
		return
	}
	defer response.Body.Close()

	if response.ContentLength > gateway.limits.MaxResponseBytes {
		terminalCode, terminalMessage = "resource_limit", "tunneled response too large"
		http.Error(w, terminalMessage, http.StatusBadGateway)
		return
	}
	removeHopByHopHeaders(response.Header)
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	written, overflow, copyErr := copyTunneledResponseBody(w, response, gateway.limits.MaxResponseBytes)
	toPublic := written
	gateway.emitStatus(request.Context(), contractv1.GatewayStatusSignal{
		ContractVersion: contractv1.ProtocolVersion, EventID: newID("status"), ObservedAt: time.Now().UTC().Format(time.RFC3339), Kind: "traffic_delta",
		DeviceID: route.DeviceID, SessionID: sess.sessionID, EndpointID: route.EndpointID, BytesFromPublic: &fromPublic, BytesToPublic: &toPublic,
	})
	if overflow {
		terminalCode, terminalMessage = "resource_limit", "tunneled response body exceeded limit"
		gateway.logger.Warn(terminalMessage, "endpoint_id", route.EndpointID, "stream_id", stream.id)
		panic(http.ErrAbortHandler)
	}
	if copyErr != nil {
		terminalCode, terminalMessage = "internal_error", "tunneled response body ended unexpectedly"
		gateway.logger.Warn(terminalMessage, "error", copyErr, "endpoint_id", route.EndpointID, "stream_id", stream.id)
		panic(http.ErrAbortHandler)
	}
	terminalReason = "completed"

}

func (gateway *Gateway) emitStatus(_ context.Context, signal contractv1.GatewayStatusSignal) {
	gateway.status.enqueue(signal)
}

func (gateway *Gateway) Close(ctx context.Context) error {
	return gateway.status.close(ctx)
}

func readProtocolFrame(ctx context.Context, conn *websocket.Conn) (contractv1.Frame, error) {
	messageType, payload, err := conn.Read(ctx)
	if err != nil {
		return contractv1.Frame{}, err
	}
	if messageType != websocket.MessageBinary {
		return contractv1.Frame{}, errors.New("protocol requires binary websocket messages")
	}
	return contractv1.DecodeFrame(payload)
}

func writeControlFrame(ctx context.Context, conn *websocket.Conn, sequence uint64, streamID uint32, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	frame, err := contractv1.EncodeFrame(contractv1.Frame{Kind: contractv1.KindControl, StreamID: streamID, Sequence: sequence, Payload: payload})
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageBinary, frame)
}

func randomBase64URL(size int) string {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func newID(prefix string) string {
	return prefix + "-" + randomBase64URL(12)
}

var errResponseHeaderTooLarge = errors.New("tunneled response headers exceed limit")

var hopByHopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func removeHopByHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if token = strings.TrimSpace(token); token != "" {
				header.Del(token)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		header.Del(name)
	}
}

func cloneRequestForTunnel(request *http.Request) *http.Request {
	cloned := request.Clone(request.Context())
	removeHopByHopHeaders(cloned.Header)
	cloned.Close = false
	cloned.TransferEncoding = nil
	cloned.Trailer = nil
	return cloned
}

type responseHeaderLimitReader struct {
	reader    io.Reader
	remaining int64
	matched   int
	done      bool
}

func newResponseHeaderLimitReader(reader io.Reader, limit int64) *responseHeaderLimitReader {
	return &responseHeaderLimitReader{reader: reader, remaining: limit}
}

func (reader *responseHeaderLimitReader) Read(data []byte) (int, error) {
	if reader.done {
		return reader.reader.Read(data)
	}
	if reader.remaining <= 0 {
		return 0, errResponseHeaderTooLarge
	}
	if int64(len(data)) > reader.remaining {
		data = data[:reader.remaining]
	}
	n, err := reader.reader.Read(data)
	reader.remaining -= int64(n)
	separator := []byte("\r\n\r\n")
	for _, value := range data[:n] {
		if value == separator[reader.matched] {
			reader.matched++
			if reader.matched == len(separator) {
				reader.done = true
				return n, err
			}
			continue
		}
		if value == separator[0] {
			reader.matched = 1
		} else {
			reader.matched = 0
		}
	}
	if !reader.done && reader.remaining == 0 {
		return n, errResponseHeaderTooLarge
	}
	return n, err
}

func copyTunneledResponseBody(writer io.Writer, response *http.Response, limit int64) (int64, bool, error) {
	if response.ContentLength >= 0 {
		if response.ContentLength == 0 {
			return 0, false, nil
		}
		written, err := io.CopyN(writer, response.Body, response.ContentLength)
		return written, false, err
	}
	written, err := io.CopyN(writer, response.Body, limit)
	if errors.Is(err, io.EOF) {
		return written, false, nil
	}
	if err != nil {
		return written, false, err
	}
	probe := make([]byte, 1)
	n, probeErr := io.ReadFull(response.Body, probe)
	if n > 0 {
		return written, true, nil
	}
	if errors.Is(probeErr, io.EOF) {
		return written, false, nil
	}
	return written, false, probeErr
}

const requestStreamChunkSize = 32 * 1024

type requestStreamWriter struct {
	ctx      context.Context
	budget   *byteBudget
	rejected *atomic.Uint64
	send     func(context.Context, []byte) error
	written  int64
}

func newRequestStreamWriter(ctx context.Context, budget *byteBudget, rejected *atomic.Uint64, send func(context.Context, []byte) error) *requestStreamWriter {
	return &requestStreamWriter{ctx: ctx, budget: budget, rejected: rejected, send: send}
}

func (writer *requestStreamWriter) Write(data []byte) (int, error) {
	total := 0
	for len(data) > 0 {
		if err := writer.ctx.Err(); err != nil {
			return total, err
		}
		size := len(data)
		if size > requestStreamChunkSize {
			size = requestStreamChunkSize
		}
		if !writer.budget.tryAcquire(int64(size)) {
			writer.rejected.Add(1)
			return total, errResourceBudget
		}
		err := writer.send(writer.ctx, data[:size])
		writer.budget.release(int64(size))
		if err != nil {
			return total, err
		}
		total += size
		writer.written += int64(size)
		data = data[size:]
	}
	return total, nil
}

func (writer *requestStreamWriter) Written() int64 { return writer.written }

type limitWriter struct {
	w         io.Writer
	remaining int64
}

func (writer *limitWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > writer.remaining {
		return 0, errors.New("serialized request exceeds limit")
	}
	n, err := writer.w.Write(data)
	writer.remaining -= int64(n)
	return n, err
}

func NewHTTPServer(address string, handler http.Handler, limits Limits) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: limits.ReadTimeout,
		ReadTimeout:       limits.ReadTimeout,
		WriteTimeout:      limits.WriteTimeout + time.Duration(limits.MaxResponseBytes/(1<<20))*time.Second,
		IdleTimeout:       limits.IdleTimeout,
		MaxHeaderBytes:    limits.MaxHeaderBytes,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}
