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
	"net"
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
	entropy  io.Reader
	draining atomic.Bool

	// mu guards the per-device session tables. Phase-3 HA allows one device
	// to hold multiple concurrent tunnels: tunnels holds every live session
	// keyed by device ID (primary plus bounded extra tunnels), while
	// primaries maps the device to the tunnel that currently owns the
	// routing stream-ID space. Replacement semantics (reconnect/resume)
	// replace per-tunnel, not per-device.
	mu             sync.RWMutex
	tunnels        map[string]map[string]*session
	primaries      map[string]*session
	handshakeSlots chan struct{}
	resources      gatewayResources
	// trustedProxyIPs is the parsed trusted public-edge set: only a request
	// arriving from one of these addresses may contribute a client address
	// through a forwarding header.
	trustedProxyIPs []net.IPNet
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
	trustedProxyIPs, err := parseTrustedProxyPeers(limits.TrustedProxyPeers)
	if err != nil {
		return nil, err
	}
	gateway := &Gateway{
		metadata:        metadata,
		limits:          limits,
		logger:          logger,
		entropy:         rand.Reader,
		tunnels:         make(map[string]map[string]*session),
		primaries:       make(map[string]*session),
		handshakeSlots:  make(chan struct{}, limits.MaxPendingHandshakes),
		resources:       newGatewayResources(limits),
		trustedProxyIPs: trustedProxyIPs,
	}
	gateway.status = newStatusExporter(status, logger, limits.MaxStatusQueueSignals, limits.StatusEmitTimeout)
	return gateway, nil
}

// Handler returns the public listener handler: public HTTP ingress plus the
// Agent WebSocket endpoint.
//
// Gateway-local operational endpoints are deliberately not registered here. A
// more specific mux pattern such as "GET /healthz" wins over the public
// ingress pattern "/" for *every* Host, so a tenant-hosted /healthz could
// never reach the tenant application. Operational endpoints are served by
// OpsHandler on a separate administrative listener instead.
func (gateway *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(agentPath, gateway.handleAgent)
	mux.HandleFunc("/", gateway.handleIngress)
	return mux
}

// OpsHandler returns the Gateway-local operational endpoints (liveness,
// readiness and low-cardinality aggregate metrics) for the separate
// administrative listener (`cmd/gateway -ops-listen`). They are never
// authorization or routing authority.
func (gateway *Gateway) OpsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", gateway.handleHealth)
	mux.HandleFunc("GET /readyz", gateway.handleReady)
	mux.HandleFunc("GET /metrics", gateway.handleMetrics)
	return mux
}

func (gateway *Gateway) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

func (gateway *Gateway) handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if gateway.draining.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"status":"not_ready"}`)
		return
	}
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
	sessions := make([]*session, 0)
	for _, deviceTunnels := range gateway.tunnels {
		for _, sess := range deviceTunnels {
			sessions = append(sessions, sess)
		}
	}
	gateway.mu.RUnlock()

	activeStreams := 0
	var latencyNanos int64 = -1
	for _, sess := range sessions {
		sess.mu.Lock()
		activeStreams += len(sess.streams)
		sess.mu.Unlock()
		if observed := sess.pingLatency.Load(); observed > 0 && (latencyNanos < 0 || observed < latencyNanos) {
			latencyNanos = observed
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_agent_sessions Current authenticated Agent sessions.\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_agent_sessions gauge\n")
	_, _ = fmt.Fprintf(w, "hooshix_gateway_agent_sessions %d\n", len(sessions))
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_agent_sessions_limit gauge\n")
	_, _ = fmt.Fprintf(w, "hooshix_gateway_agent_sessions_limit %d\n", gateway.limits.MaxAgentSessions)
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_active_tunnels Current live Agent tunnel connections (one agent may hold multiple bounded tunnels for HA failover).\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_active_tunnels gauge\n")
	_, _ = fmt.Fprintf(w, "hooshix_gateway_active_tunnels %d\n", len(sessions))
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_active_streams Current active tunnel streams.\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_active_streams gauge\n")
	_, _ = fmt.Fprintf(w, "hooshix_gateway_active_streams %d\n", activeStreams)
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_pending_handshakes Current Agent handshakes consuming bounded slots.\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_pending_handshakes gauge\n")
	_, _ = fmt.Fprintf(w, "hooshix_gateway_pending_handshakes %d\n", len(gateway.handshakeSlots))
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_pending_handshakes_limit gauge\n")
	_, _ = fmt.Fprintf(w, "hooshix_gateway_pending_handshakes_limit %d\n", gateway.limits.MaxPendingHandshakes)

	queueUsed, queueLimit, _ := gateway.resources.queueBytes.Snapshot()
	ingressUsed, ingressLimit, _ := gateway.resources.ingressBytes.Snapshot()
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
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_handshake_rejections_total counter\nhooshix_gateway_handshake_rejections_total %d\n", gateway.resources.handshakeRejects.Load()+gateway.resources.handshakeRate.Rejected()+gateway.resources.handshakeDeviceAdmission.Rejected()+gateway.resources.preAuthRate.Rejected())
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_ingress_rejections_total counter\nhooshix_gateway_ingress_rejections_total %d\n", gateway.resources.ingressRejects.Load()+gateway.resources.ingressRate.Rejected()+gateway.resources.ingressRouteAdmission.Rejected()+gateway.resources.ingressDeviceAdmission.Rejected())
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_session_capacity_rejections_total counter\nhooshix_gateway_session_capacity_rejections_total %d\n", gateway.resources.sessionRejects.Load())
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_health_reports_total Total bounded Agent health_report control messages accepted.\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_health_reports_total counter\nhooshix_gateway_health_reports_total %d\n", gateway.resources.healthReports.Load())
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_reconnects_total Total authenticated Agent reconnects that replaced a live session (full handshake or resume).\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_reconnects_total counter\nhooshix_gateway_reconnects_total %d\n", gateway.resources.reconnects.Load())
	// Byte counters are process-lifetime monotonic (Prometheus `_total`
	// contract): the gateway-level accumulators are authoritative and never
	// decrease when sessions disconnect. Live-session accumulation would
	// reset on every resume/replacement and break rate/alert correctness.
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_tunnel_bytes_from_agents_total Total protocol data-frame bytes received from Agents.\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_tunnel_bytes_from_agents_total counter\nhooshix_gateway_tunnel_bytes_from_agents_total %d\n", gateway.resources.agentBytes.Load())
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_tunnel_bytes_to_agents_total Total protocol data-frame bytes sent toward Agents.\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_tunnel_bytes_to_agents_total counter\nhooshix_gateway_tunnel_bytes_to_agents_total %d\n", gateway.resources.publicBytes.Load())
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_session_latency_ms Best observed heartbeat round-trip across live sessions in milliseconds; -1 while no pong has completed.\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_session_latency_ms gauge\n")
	if latencyNanos >= 0 {
		_, _ = fmt.Fprintf(w, "hooshix_gateway_session_latency_ms %.3f\n", float64(latencyNanos)/1e6)
	} else {
		_, _ = fmt.Fprintf(w, "hooshix_gateway_session_latency_ms -1\n")
	}
	statusQueued, statusLimit, statusDropped, statusFailures := gateway.status.snapshot()
	_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_status_queue_depth Current queued status signals waiting for asynchronous export.\n")
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_status_queue_depth gauge\nhooshix_gateway_status_queue_depth %d\n", statusQueued)
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_status_queue_limit gauge\nhooshix_gateway_status_queue_limit %d\n", statusLimit)
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_status_dropped_total counter\nhooshix_gateway_status_dropped_total %d\n", statusDropped)
	_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_status_export_failures_total counter\nhooshix_gateway_status_export_failures_total %d\n", statusFailures)
	if metadataStats, ok := gateway.metadata.(interface {
		MetadataStats(time.Time) LiveMetadataStats
	}); ok {
		stats := metadataStats.MetadataStats(time.Now().UTC())
		fresh := 0
		if stats.Fresh {
			fresh = 1
		}
		_, _ = fmt.Fprintf(w, "# HELP hooshix_gateway_metadata_fresh Whether the active live metadata generation is within its freshness deadline.\n")
		_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_metadata_fresh gauge\nhooshix_gateway_metadata_fresh %d\n", fresh)
		_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_metadata_snapshot_age_seconds gauge\nhooshix_gateway_metadata_snapshot_age_seconds %.3f\n", stats.SnapshotAge.Seconds())
		_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_metadata_refresh_successes_total counter\nhooshix_gateway_metadata_refresh_successes_total %d\n", stats.RefreshSuccesses)
		_, _ = fmt.Fprintf(w, "# TYPE hooshix_gateway_metadata_refresh_failures_total counter\nhooshix_gateway_metadata_refresh_failures_total %d\n", stats.RefreshFailures)
	}
}

func (gateway *Gateway) handleAgent(w http.ResponseWriter, request *http.Request) {
	if gateway.draining.Load() {
		http.Error(w, "gateway is draining", http.StatusServiceUnavailable)
		return
	}
	// Pre-authentication admission is keyed on the trusted peer and applied
	// before slot acquisition: an unauthenticated socket that sends a
	// valid-shaped preface and then stalls must not be able to cycle the
	// bounded global handshake slots at will.
	peer := gateway.peerAddress(request)
	if !gateway.resources.preAuthRate.Allow(peer, time.Now()) {
		http.Error(w, "too many pending handshakes", http.StatusTooManyRequests)
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
		Subprotocols:    []string{contractv1.ResumeProofSubprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		gateway.logger.Warn("agent websocket accept failed", "error", err)
		return
	}
	conn.SetReadLimit(contractv1.HeaderSize + contractv1.MaxDataPayload)

	ctx, cancel := context.WithTimeout(request.Context(), gateway.limits.HandshakeTimeout)
	defer cancel()
	prefaceCtx, prefaceCancel := context.WithTimeout(ctx, handshakePrefaceTimeout(gateway.limits.HandshakeTimeout))
	candidate, resume, err := gateway.readPreface(prefaceCtx, conn)
	prefaceCancel()
	if err != nil {
		if metadataTemporarilyUnavailable(err) {
			_ = conn.Close(websocket.StatusTryAgainLater, "authorization metadata unavailable")
			return
		}
		if errors.Is(err, errResumeUnavailable) {
			// An old or stale Agent whose resume proof no longer verifies
			// must fall back to a full client_hello handshake; the resume
			// fast path is best-effort and never a permanent rejection.
			gateway.logger.Info("agent resume preface unavailable", "error", err)
			_ = conn.Close(websocket.StatusTryAgainLater, "resume unavailable; reconnect with full handshake")
			return
		}
		gateway.logger.Warn("agent pre-authentication failed", "error", err)
		_ = conn.Close(websocket.StatusPolicyViolation, "authentication failed")
		return
	}

	now := time.Now()
	if !gateway.resources.handshakeRate.Allow(now) {
		_ = conn.Close(websocket.StatusTryAgainLater, "agent handshake rate limit exceeded")
		return
	}
	resumeDeviceID := candidate.record.DeviceID
	if resume != nil {
		resumeDeviceID = resume.DeviceID
	}
	deviceAdmission := gateway.resources.handshakeDeviceAdmission.TryAcquire(resumeDeviceID, now)
	if deviceAdmission != admissionAccepted {
		_ = conn.Close(websocket.StatusTryAgainLater, "device handshake admission limit exceeded")
		return
	}
	sess, err := gateway.completeAuthenticationOrResume(ctx, conn, candidate, resume)
	gateway.resources.handshakeDeviceAdmission.Release(resumeDeviceID)
	releaseHandshakeSlot()
	cancel()
	if errors.Is(err, errResumeUnavailable) {
		// Resume is a best-effort fast path: when the target session no
		// longer exists the Agent must fall back to a fresh full handshake
		// on a new connection. Closing with TryAgainLater keeps the Agent's
		// bounded reconnect behavior instead of treating this as permanent.
		gateway.logger.Info("agent session resume unavailable", "device_id", resumeDeviceID)
		_ = conn.Close(websocket.StatusTryAgainLater, "resume unavailable; reconnect with full handshake")
		return
	}
	if err != nil {
		gateway.logger.Warn("agent authentication failed", "error", err)
		if metadataTemporarilyUnavailable(err) {
			_ = conn.Close(websocket.StatusTryAgainLater, "authorization metadata unavailable")
			return
		}
		_ = conn.Close(websocket.StatusPolicyViolation, "authentication failed")
		return
	}

	if err := gateway.registerSession(sess); err != nil {
		gateway.logger.Warn("agent session registration rejected", "device_id", sess.deviceID, "error", err)
		_ = conn.Close(websocket.StatusTryAgainLater, "session capacity reached")
		// The session object already owns a writer goroutine and its
		// channels: without an explicit teardown the rejected handshake would
		// leak that goroutine, the session and its channels on every
		// capacity-rejected authentication.
		sess.forceClose()
		return
	}
	defer gateway.unregisterSession(sess)

	gateway.emitStatus(context.Background(), contractv1.GatewayStatusSignal{
		ContractVersion: contractv1.ProtocolVersion,
		ObservedAt:      time.Now().UTC().Format(time.RFC3339),
		Kind:            "session_connected",
		DeviceID:        sess.deviceID,
		SessionID:       sess.sessionID,
	})

	gateway.logger.Info("agent session authenticated", "device_id", sess.deviceID, "session_id", sess.sessionID)
	sess.run(request.Context())

	gateway.emitStatus(context.Background(), contractv1.GatewayStatusSignal{
		ContractVersion: contractv1.ProtocolVersion,
		ObservedAt:      time.Now().UTC().Format(time.RFC3339),
		Kind:            "session_disconnected",
		DeviceID:        sess.deviceID,
		SessionID:       sess.sessionID,
	})
}

type authorizedHandshake struct {
	hello   contractv1.ClientHello
	record  contractv1.DeviceSessionAuthorization
	inbound contractv1.SequenceTracker
}

func handshakePrefaceTimeout(total time.Duration) time.Duration {
	timeout := total / 4
	if timeout <= 0 || timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	if timeout > total {
		return total
	}
	return timeout
}

// readPreface consumes the first session control frame and routes it as
// either a fresh client_hello preface or a resume_session fast-path request.
// The returned resume value is non-nil only for the resume path.
func (gateway *Gateway) readPreface(ctx context.Context, conn *websocket.Conn) (authorizedHandshake, *contractv1.ResumeSession, error) {
	var candidate authorizedHandshake
	var resume contractv1.ResumeSession
	first, err := readProtocolFrame(ctx, conn)
	if err != nil {
		return candidate, nil, err
	}
	if err := candidate.inbound.Accept(first.Sequence); err != nil {
		return candidate, nil, err
	}
	if first.Kind != contractv1.KindControl || first.StreamID != 0 {
		return candidate, nil, errors.New("first frame must be session control")
	}
	if err := contractv1.ValidateControlPayload(first.Payload, 0, time.Now().UTC()); err != nil {
		// A resume preface that does not satisfy the *current* resume
		// contract (for example an Agent that does not yet bind the
		// Gateway-issued resume challenge) must fail closed as an
		// unavailable resume, so the Agent falls back to a full client_hello
		// handshake instead of being rejected as an authentication failure.
		if resumeEnvelopeMessageType(first.Payload) == "resume_session" {
			return candidate, nil, fmt.Errorf("%w: %w", errResumeUnavailable, err)
		}
		return candidate, nil, err
	}
	if resumeEnvelopeMessageType(first.Payload) == "resume_session" {
		if err := json.Unmarshal(first.Payload, &resume); err != nil {
			return candidate, nil, fmt.Errorf("%w: %w", errResumeUnavailable, err)
		}
		return candidate, &resume, nil
	}
	candidate.hello, err = contractv1.DecodeClientHello(first.Payload)
	if err != nil {
		return candidate, nil, err
	}
	candidate.record, err = gateway.metadata.Authorization(ctx, candidate.hello.AuthorizationID, candidate.hello.DeviceID, candidate.hello.TokenID, time.Now().UTC())
	if err != nil {
		return candidate, nil, fmt.Errorf("authorization lookup: %w", err)
	}
	if !contractv1.MatchSessionToken(candidate.record, candidate.hello.SessionToken) {
		return candidate, nil, errors.New("session token mismatch")
	}
	return candidate, nil, nil
}

// resumeEnvelopeMessageType peeks at only the message_type member of a
// preface payload. It is deliberately lenient: it decides which *fallback*
// applies to an already-rejected frame, never whether a frame is accepted.
func resumeEnvelopeMessageType(payload []byte) string {
	var envelope struct {
		MessageType string `json:"message_type"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return ""
	}
	return envelope.MessageType
}

// errResumeUnavailable signals that the resume target session is gone; the
// caller must close with TryAgainLater so the Agent falls back to a full
// handshake on its next bounded reconnect attempt.
var errResumeUnavailable = errors.New("resume target session unavailable")

func metadataTemporarilyUnavailable(err error) bool {
	return errors.Is(err, ErrMetadataUnavailable) || errors.Is(err, ErrMetadataStale)
}

func (gateway *Gateway) completeAuthenticationOrResume(ctx context.Context, conn *websocket.Conn, candidate authorizedHandshake, resume *contractv1.ResumeSession) (*session, error) {
	if resume == nil {
		return gateway.completeAuthentication(ctx, conn, candidate)
	}
	return gateway.resumeSession(ctx, conn, candidate, *resume)
}

// resumeSession implements the Phase-2 session-resume fast path. It accepts
// only when the referenced session is still live and authorized, the current
// authorization record still matches and is active, the presented resume
// proof is within its acceptance window, the resume challenge the Gateway
// issued for this session identity is bound into the signature, and no
// revocation applies. Any mismatch fails closed to errResumeUnavailable (never
// to a half-resumed session).
func (gateway *Gateway) resumeSession(ctx context.Context, conn *websocket.Conn, candidate authorizedHandshake, resume contractv1.ResumeSession) (*session, error) {
	if conn.Subprotocol() != contractv1.ResumeProofSubprotocol {
		return nil, errResumeUnavailable
	}
	gateway.mu.RLock()
	existing := gateway.tunnels[resume.DeviceID][resume.SessionID]
	gateway.mu.RUnlock()
	if existing == nil || !existing.authorized.Load() {
		return nil, errResumeUnavailable
	}
	// One-shot replay protection: consume the armed resume slot before any
	// further validation. A replayed/captured resume_session frame can never
	// replace the live connection a second time; the slot is rearmed only
	// when this resume succeeds (see resumeInto) or on a fresh handshake.
	if !existing.resumeArmed.CompareAndSwap(true, false) {
		return nil, errResumeUnavailable
	}
	if existing.deviceID != resume.DeviceID || existing.authorizationID != resume.AuthorizationID || existing.tokenID != resume.TokenID {
		return nil, errors.New("resume subject mismatch")
	}

	// The proof must bind the challenge the Gateway issued over the previous
	// transport. Without it a captured resume frame would be a bearer token
	// usable for the whole session lifetime.
	if !contractv1.MatchResumeChallenge(existing.currentResumeChallenge(), resume.ResumeChallenge) {
		// A stale/burned challenge is not proof of an attack (an Agent that
		// resumed twice, or a rotated challenge), so the one-shot slot is
		// restored and the Agent falls back to a full handshake.
		existing.resumeArmed.Store(true)
		return nil, fmt.Errorf("%w: resume challenge mismatch", errResumeUnavailable)
	}
	// Short acceptance window: a proof issued outside the window is dead even
	// if a replayed frame is otherwise intact. The timestamp is Agent-supplied,
	// so a badly skewed Agent clock degrades to the full handshake fallback
	// (fail closed) rather than granting anything.
	issuedAt, err := contractv1.ResumeIssuedAt(resume)
	if err != nil {
		existing.resumeArmed.Store(true)
		return nil, fmt.Errorf("%w: %v", errResumeUnavailable, err)
	}
	if skew := time.Since(issuedAt); skew > gateway.limits.ResumeAcceptanceWindow || skew < -gateway.limits.ResumeAcceptanceWindow {
		existing.resumeArmed.Store(true)
		return nil, fmt.Errorf("%w: resume proof outside acceptance window", errResumeUnavailable)
	}

	// The full authorization must still be current: same record identity,
	// active, unexpired, and not revoked.
	record, err := gateway.metadata.Authorization(ctx, resume.AuthorizationID, resume.DeviceID, resume.TokenID, time.Now().UTC())
	if err != nil {
		// Authorization lookup failures are authoritative rejections for a
		// resume attempt: a resume may never bypass fresh validation. The
		// consumed resume slot is returned so a transient metadata outage
		// does not lock the legitimate Agent out of the fast path.
		existing.resumeArmed.Store(true)
		return nil, fmt.Errorf("resume authorization lookup: %w", err)
	}
	if record.AuthorizationID != resume.AuthorizationID || record.DeviceID != resume.DeviceID || record.TokenID != resume.TokenID {
		existing.resumeArmed.Store(true)
		return nil, errors.New("resume authorization mismatch")
	}
	if record.Disabled {
		existing.resumeArmed.Store(true)
		return nil, errors.New("resume authorization disabled")
	}
	if err := contractv1.VerifyResumeSignature(record.DevicePublicKey, resume); err != nil {
		// A failed signature does not burn the legitimate resume slot: the
		// real Agent may still be trying to reconnect while an attacker is
		// probing with garbage signatures. Signature verification failure is
		// therefore not treated as a consumed attempt.
		existing.resumeArmed.Store(true)
		return nil, err
	}

	// The accepted proof is consumed and rotated: a captured frame can never
	// be replayed against the same identity again.
	nextChallenge, err := gateway.randomBase64URL(32)
	if err != nil {
		existing.resumeArmed.Store(true)
		return nil, fmt.Errorf("generate resume challenge: %w", err)
	}

	// From here the new connection takes over the session identity. The
	// existing WebSocket is closed outside the registry lock by the same
	// registerSession replacement semantics as a normal reconnect.
	resumed := existing.resumeInto(conn, candidate.inbound, nextChallenge)
	if resumed == nil {
		existing.resumeArmed.Store(true)
		return nil, errResumeUnavailable
	}

	// Sequence numbering restarts on the new connection (independent
	// per-direction rule): the resume reply is sequence 1, issued by the
	// session's single writer goroutine like every other post-handshake frame,
	// so the resumed session never has two concurrent writers.
	resumedControl := contractv1.SessionResumed{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "session_resumed",
		SessionID:       resumed.sessionID,
		NextSequence:    2,
		ResumedAt:       time.Now().UTC().Format(time.RFC3339),
		ResumeChallenge: nextChallenge,
	}
	if err := resumed.sendControl(ctx, 0, resumedControl); err != nil {
		resumed.forceClose()
		return nil, err
	}
	gateway.logger.Info("agent session resumed", "device_id", resumed.deviceID, "session_id", resumed.sessionID)
	return resumed, nil
}

func (gateway *Gateway) completeAuthentication(ctx context.Context, conn *websocket.Conn, candidate authorizedHandshake) (*session, error) {
	sessionID, err := gateway.newID("session")
	if err != nil {
		return nil, fmt.Errorf("generate session ID: %w", err)
	}
	serverNonce, err := gateway.randomBase64URL(32)
	if err != nil {
		return nil, fmt.Errorf("generate server nonce: %w", err)
	}
	challenge := contractv1.ServerChallenge{
		ContractVersion: contractv1.ProtocolVersion,
		MessageType:     "server_challenge",
		SessionID:       sessionID,
		ServerNonce:     serverNonce,
		ExpiresAt:       time.Now().UTC().Add(gateway.limits.HandshakeTimeout).Format(time.RFC3339),
	}
	if err := writeControlFrame(ctx, conn, 1, 0, challenge); err != nil {
		return nil, err
	}

	second, err := readProtocolFrame(ctx, conn)
	if err != nil {
		return nil, err
	}
	if err := candidate.inbound.Accept(second.Sequence); err != nil {
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

	// Live authorization can change while the challenge is in flight. Re-resolve the current
	// authority immediately before creating a routable session so a revoked/disabled/rotated
	// authorization cannot complete using the earlier client_hello snapshot.
	currentRecord, err := gateway.metadata.Authorization(ctx, candidate.hello.AuthorizationID, candidate.hello.DeviceID, candidate.hello.TokenID, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("authorization changed during handshake: %w", err)
	}
	if !contractv1.MatchSessionToken(currentRecord, candidate.hello.SessionToken) {
		return nil, errors.New("session token no longer matches current authorization")
	}
	if err := contractv1.VerifyClientAuthSignature(currentRecord.DevicePublicKey, candidate.hello, challenge, auth); err != nil {
		return nil, err
	}
	authorizationExpiresAt, err := time.Parse(time.RFC3339, currentRecord.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse authorization expiry: %w", err)
	}

	// The Gateway issues the resume proof for this transport at session
	// establishment. The Agent must bind it into its next resume_session
	// transcript, and the Gateway rotates it on every accepted resume, so a
	// captured resume frame is not replayable for the session lifetime.
	resumeChallenge := ""
	if conn.Subprotocol() == contractv1.ResumeProofSubprotocol {
		resumeChallenge, err = gateway.randomBase64URL(32)
		if err != nil {
			return nil, fmt.Errorf("generate resume challenge: %w", err)
		}
	}

	ready := contractv1.SessionReady{
		ContractVersion:          contractv1.ProtocolVersion,
		MessageType:              "session_ready",
		SessionID:                challenge.SessionID,
		HeartbeatIntervalSeconds: int(gateway.limits.HeartbeatInterval / time.Second),
		IdleTimeoutSeconds:       int(gateway.limits.IdleTimeout / time.Second),
		ResumeChallenge:          resumeChallenge,
	}
	if err := writeControlFrame(ctx, conn, 2, 0, ready); err != nil {
		return nil, err
	}

	return newSession(gateway, conn, currentRecord.DeviceID, challenge.SessionID, currentRecord.AuthorizationID, currentRecord.TokenID, authorizationExpiresAt, candidate.inbound, 2, resumeChallenge), nil
}

// registerSession admits a tunnel session under the Phase-3 HA model. A
// device may hold multiple bounded tunnels (MaxTunnelsPerDevice): a resume
// replaces its own tunnel in place, and a fresh full handshake from a device
// that already owns a dead primary takes over routing. Extra tunnels beyond
// the routing primary are standby capacity; the bounded device budget fails
// closed instead of evicting the routing primary.
func (gateway *Gateway) registerSession(sess *session) error {
	gateway.mu.Lock()
	if gateway.draining.Load() {
		gateway.mu.Unlock()
		return errors.New("gateway is draining")
	}
	deviceTunnels := gateway.tunnels[sess.deviceID]
	primary := gateway.primaries[sess.deviceID]
	replaced, hasReplaced := deviceTunnels[sess.sessionID]
	totalSessions := 0
	for _, tunnels := range gateway.tunnels {
		totalSessions += len(tunnels)
	}
	isReconnect := replaced != nil && replaced != sess
	isNewTunnel := !hasReplaced
	if isNewTunnel && totalSessions >= gateway.limits.MaxAgentSessions {
		// The global capacity bound applies to every new tunnel: a device
		// that already owns tunnels must not bypass the session ceiling by
		// adding standby capacity (the effective limit would otherwise grow
		// to MaxAgentSessions * MaxTunnelsPerDevice).
		gateway.resources.sessionRejects.Add(1)
		gateway.mu.Unlock()
		return errors.New("agent session capacity reached")
	}
	if isNewTunnel && len(deviceTunnels) >= gateway.limits.MaxTunnelsPerDevice {
		// The device HA budget is exhausted: recycle the oldest standby
		// tunnel. The routing primary is never evicted by a standby arrival;
		// when only the primary remains, fail closed so the Agent's bounded
		// reconnect schedule retries.
		victim := oldestStandby(deviceTunnels, primary)
		if victim == nil {
			gateway.resources.sessionRejects.Add(1)
			gateway.mu.Unlock()
			return errors.New("device tunnel capacity reached")
		}
		replaced = victim
		isReconnect = false
		// Drop the victim inside the same critical section that admits the
		// replacement: the device tunnel count must never transiently exceed
		// MaxTunnelsPerDevice (a concurrent registration would otherwise fail
		// closed against a budget that is only momentarily oversubscribed).
		delete(deviceTunnels, victim.sessionID)
	}
	if deviceTunnels == nil {
		deviceTunnels = make(map[string]*session)
		gateway.tunnels[sess.deviceID] = deviceTunnels
	}
	deviceTunnels[sess.sessionID] = sess
	if primary == nil || (isReconnect && primary == replaced) {
		// Either the first tunnel owns routing for the device, or the
		// replaced tunnel was the routing primary (reconnect/resume keeps
		// routing continuity with the session identity).
		gateway.primaries[sess.deviceID] = sess
	}
	gateway.mu.Unlock()

	if replaced != nil && replaced != sess {
		if isReconnect {
			// A reconnect (fresh handshake or resume) replaced a live
			// tunnel: count it as an agent-driven reconnect.
			gateway.resources.reconnects.Add(1)
		}
		replaced.failAll(errors.New("agent session replaced by reconnect"))
		replaced.close(websocket.StatusNormalClosure, "replaced by reconnect")
	}
	return nil
}

// oldestStandby returns the tunnel that is neither the routing primary nor
// the newest arrival; a device with only its primary returns nil.
func oldestStandby(deviceTunnels map[string]*session, primary *session) *session {
	var victim *session
	for _, candidate := range deviceTunnels {
		if candidate == primary {
			continue
		}
		if victim == nil || candidate.lastSeen.Load() < victim.lastSeen.Load() {
			victim = candidate
		}
	}
	return victim
}

func (gateway *Gateway) unregisterSession(sess *session) {
	gateway.mu.Lock()
	deviceTunnels := gateway.tunnels[sess.deviceID]
	if deviceTunnels == nil {
		gateway.mu.Unlock()
		return
	}
	if current, ok := deviceTunnels[sess.sessionID]; !ok || current != sess {
		gateway.mu.Unlock()
		return
	}
	delete(deviceTunnels, sess.sessionID)
	if len(deviceTunnels) == 0 {
		delete(gateway.tunnels, sess.deviceID)
	}
	if gateway.primaries[sess.deviceID] == sess {
		delete(gateway.primaries, sess.deviceID)
		// Promote the oldest surviving tunnel so device routing survives the
		// primary transport loss without a fresh handshake.
		for _, candidate := range deviceTunnels {
			if gateway.primaries[sess.deviceID] == nil || candidate.lastSeen.Load() < gateway.primaries[sess.deviceID].lastSeen.Load() {
				gateway.primaries[sess.deviceID] = candidate
			}
		}
	}
	gateway.mu.Unlock()
}

// sessionForDevice returns a routable tunnel for the device: an authorized,
// unexpired session whose stream space owns ingress routing. The routing
// primary is preferred; when it is gone or no longer routable (for example a
// just-terminated session that is still completing its close handshake), the
// newest routable standby tunnel is used so ingress fails over without
// waiting for the primary's registry entry to disappear.
func (gateway *Gateway) sessionForDevice(deviceID string) *session {
	gateway.mu.RLock()
	primary := gateway.primaries[deviceID]
	tunnels := gateway.tunnels[deviceID]
	var standby *session
	for _, candidate := range tunnels {
		if candidate == primary {
			continue
		}
		if standby == nil || candidate.lastSeen.Load() > standby.lastSeen.Load() {
			standby = candidate
		}
	}
	gateway.mu.RUnlock()

	if routableSession(primary) {
		return primary
	}
	if routableSession(standby) {
		return standby
	}
	return nil
}

func routableSession(sess *session) bool {
	if sess == nil || !sess.authorized.Load() {
		return false
	}
	if !sess.authorizationExpiresAt.IsZero() && !time.Now().UTC().Before(sess.authorizationExpiresAt) {
		return false
	}
	return true
}

func (gateway *Gateway) handleIngress(w http.ResponseWriter, request *http.Request) {
	if request.URL.Path == agentPath || strings.HasPrefix(request.URL.Path, agentPath+"/") {
		// Defence in depth for the one reserved Gateway-local namespace: the
		// Agent endpoint is served by its own mux pattern and must never be
		// resolved as a tenant route. The operational endpoints are NOT
		// reserved here: they live on the separate administrative listener, so
		// a tenant host keeps its own /healthz, /readyz and /metrics routes.
		http.NotFound(w, request)
		return
	}
	if gateway.draining.Load() {
		http.Error(w, "gateway is draining", http.StatusServiceUnavailable)
		return
	}
	if request.ContentLength > gateway.limits.MaxRequestBytes {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
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

	routeAdmission := gateway.resources.ingressRouteAdmission.TryAcquire(route.AssignmentID, now)
	if routeAdmission != admissionAccepted {
		status := http.StatusServiceUnavailable
		message := "route ingress concurrency limit reached"
		if routeAdmission == admissionRejectedRate {
			status = http.StatusTooManyRequests
			message = "route ingress rate limit exceeded"
		}
		http.Error(w, message, status)
		return
	}
	defer gateway.resources.ingressRouteAdmission.Release(route.AssignmentID)

	deviceAdmission := gateway.resources.ingressDeviceAdmission.TryAcquire(route.DeviceID, now)
	if deviceAdmission != admissionAccepted {
		status := http.StatusServiceUnavailable
		message := "device ingress concurrency limit reached"
		if deviceAdmission == admissionRejectedRate {
			status = http.StatusTooManyRequests
			message = "device ingress rate limit exceeded"
		}
		http.Error(w, message, status)
		return
	}
	defer gateway.resources.ingressDeviceAdmission.Release(route.DeviceID)

	if !gateway.resources.ingressRate.Allow(now) {
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

	// The stream (and therefore the bytes it may still retain) is bound to the
	// public request context *and* to a cancel this handler owns, so returning
	// always detaches the stream regardless of what the Agent does. Without
	// this a stalled or hostile Agent that keeps answering heartbeats would
	// hold one of the bounded global ingress slots forever.
	responseCtx, cancelResponse := context.WithCancel(request.Context())
	defer cancelResponse()

	stream, err := sess.openStream(responseCtx, route)
	if err != nil {
		http.Error(w, "stream unavailable", http.StatusServiceUnavailable)
		return
	}
	// Registered before the terminal defer below, so it runs after the stream
	// has been detached: whatever the reader left behind is released once the
	// handler has stopped reading.
	defer stream.discardRetained()
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

	controller := http.NewResponseController(w)
	tunnelRequest := gateway.cloneRequestForTunnel(request, route)
	// The request body is read under a per-read idle deadline instead of a
	// whole-request deadline, so a large upload is not forced to complete
	// inside one fixed budget while a stalled client is still bounded.
	//
	// A request without a body is deliberately not wrapped: http.Request.Write
	// only reads the body when it is not http.NoBody, and every read of the
	// wrapper arms a read deadline on the public connection. Go's server starts
	// its background read as soon as a bodyless request's handler begins, so
	// such a deadline stays armed through the whole response phase and, once it
	// expires, the background read cancels the request context of a healthy
	// tunneled response.
	if request.Body != nil && request.Body != http.NoBody {
		tunnelRequest.Body = http.MaxBytesReader(w, newIdleDeadlineReader(request.Body, controller, gateway.limits.ReadTimeout), gateway.limits.MaxRequestBytes)
	}
	streamWriter := newRequestStreamWriter(request.Context(), gateway.resources.ingressBytes, &gateway.resources.ingressRejects, func(ctx context.Context, payload []byte) error {
		return sess.sendBytes(ctx, stream.id, payload)
	})
	limited := &limitWriter{w: streamWriter, remaining: gateway.limits.MaxRequestBytes + int64(gateway.limits.MaxHeaderBytes)}
	writeErr := tunnelRequest.Write(limited)
	// The request-write phase is the only phase that may hold the idle read
	// deadline, so it is cleared once serialization is done: the response phase
	// is bounded by its own inactivity deadline, and a read deadline left armed
	// here would fire ReadTimeout into it.
	_ = controller.SetReadDeadline(time.Time{})
	if writeErr != nil {
		if errors.Is(writeErr, errResourceBudget) {
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

	// Response phase: bounded by inactivity in both directions, so neither a
	// stalled Agent nor a public client that stops reading can pin the slot.
	phase := newResponsePhase(gateway.limits.ResponsePhaseTimeout, cancelResponse)
	defer phase.stop()
	headerLimited := newResponseHeaderLimitReader(&progressReader{reader: stream, phase: phase}, int64(gateway.limits.MaxHeaderBytes))
	response, err := http.ReadResponse(bufio.NewReader(headerLimited), tunnelRequest)
	if err != nil {
		if errors.Is(err, errResponseHeaderTooLarge) {
			terminalCode, terminalMessage = "resource_limit", "tunneled response headers too large"
			gateway.logger.Warn(terminalMessage, "error", err, "endpoint_id", route.EndpointID, "stream_id", stream.id)
			http.Error(w, terminalMessage, http.StatusBadGateway)
			return
		}
		if responseCtx.Err() != nil && request.Context().Err() == nil {
			terminalCode, terminalMessage = "resource_limit", "tunneled response phase deadline exceeded"
			gateway.logger.Warn(terminalMessage, "endpoint_id", route.EndpointID, "stream_id", stream.id)
			http.Error(w, terminalMessage, http.StatusGatewayTimeout)
			return
		}
		terminalCode, terminalMessage = "protocol_error", "invalid tunneled response"
		gateway.logger.Warn(terminalMessage, "error", err, "endpoint_id", route.EndpointID, "stream_id", stream.id)
		http.Error(w, terminalMessage, http.StatusBadGateway)
		return
	}
	defer response.Body.Close()

	if statusErr := validateTunneledStatus(response.StatusCode); statusErr != nil {
		terminalCode, terminalMessage = "protocol_error", "tunneled response status outside 200..599"
		gateway.logger.Warn(terminalMessage, "error", statusErr, "status", response.StatusCode, "endpoint_id", route.EndpointID, "stream_id", stream.id)
		http.Error(w, terminalMessage, http.StatusBadGateway)
		return
	}
	if responseHasBody(response) && response.ContentLength > gateway.limits.MaxResponseBytes {
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
	_ = controller.SetWriteDeadline(time.Now().Add(gateway.limits.WriteTimeout))
	w.WriteHeader(response.StatusCode)
	// SSE events must reach the caller while the upstream stream stays open.
	flushEvents := strings.EqualFold(strings.TrimSpace(strings.SplitN(response.Header.Get("Content-Type"), ";", 2)[0]), "text/event-stream")
	if flushEvents {
		if err := controller.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
			panic(http.ErrAbortHandler)
		}
	}
	written, overflow, copyErr := copyTunneledResponseBody(&progressWriter{writer: w, controller: controller, timeout: gateway.limits.WriteTimeout, phase: phase, flush: flushEvents}, response, gateway.limits.MaxResponseBytes)
	toPublic := written
	gateway.emitStatus(request.Context(), contractv1.GatewayStatusSignal{
		ContractVersion: contractv1.ProtocolVersion, ObservedAt: time.Now().UTC().Format(time.RFC3339), Kind: "traffic_delta",
		DeviceID: route.DeviceID, SessionID: sess.sessionID, EndpointID: route.EndpointID, BytesFromPublic: &fromPublic, BytesToPublic: &toPublic,
	})
	if overflow {
		terminalCode, terminalMessage = "resource_limit", "tunneled response body exceeded limit"
		gateway.logger.Warn(terminalMessage, "endpoint_id", route.EndpointID, "stream_id", stream.id)
		panic(http.ErrAbortHandler)
	}
	if copyErr != nil {
		if responseCtx.Err() != nil && request.Context().Err() == nil {
			terminalCode, terminalMessage = "resource_limit", "tunneled response phase deadline exceeded"
		} else {
			terminalCode, terminalMessage = "internal_error", "tunneled response body ended unexpectedly"
		}
		gateway.logger.Warn(terminalMessage, "error", copyErr, "endpoint_id", route.EndpointID, "stream_id", stream.id,
			"content_length", response.ContentLength, "written_bytes", written, "from_public_bytes", fromPublic)
		panic(http.ErrAbortHandler)
	}
	terminalReason = "completed"

}

// validateTunneledStatus enforces the public status-line allowlist. Nothing
// below 200 is forwardable: a 1xx (including 101 Switching Protocols) would
// leave the public connection in a state the Gateway does not model, and
// response.StatusCode is Agent-controlled. Go's own net/http only bounds the
// value to 100..999.
func validateTunneledStatus(status int) error {
	if status < 200 || status > 599 {
		return fmt.Errorf("tunneled response status %d is not a final status", status)
	}
	return nil
}

func (gateway *Gateway) emitStatus(_ context.Context, signal contractv1.GatewayStatusSignal) {
	if signal.EventID == "" {
		eventID, err := gateway.newID("status")
		if err != nil {
			gateway.logger.Warn("status signal ID generation failed", "error", err, "kind", signal.Kind)
			return
		}
		signal.EventID = eventID
	}
	gateway.status.enqueue(signal)
}

var errGatewayShuttingDown = errors.New("gateway shutting down")

func (gateway *Gateway) BeginDrain() {
	gateway.draining.Store(true)
}

func (gateway *Gateway) Close(ctx context.Context) error {
	gateway.BeginDrain()

	gateway.mu.Lock()
	sessions := make([]*session, 0)
	for _, deviceTunnels := range gateway.tunnels {
		for _, sess := range deviceTunnels {
			sessions = append(sessions, sess)
		}
	}
	gateway.tunnels = make(map[string]map[string]*session)
	gateway.primaries = make(map[string]*session)
	gateway.mu.Unlock()

	for _, sess := range sessions {
		sess.failAll(errGatewayShuttingDown)
	}

	drained := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		wg.Add(len(sessions))
		for _, sess := range sessions {
			sess := sess
			go func() {
				defer wg.Done()
				sess.close(websocket.StatusGoingAway, "gateway shutting down")
			}()
		}
		wg.Wait()
		close(drained)
	}()

	var drainErr error
	select {
	case <-drained:
	case <-ctx.Done():
		drainErr = ctx.Err()
		for _, sess := range sessions {
			sess.forceClose()
		}
	}

	statusErr := gateway.status.close(ctx)
	return errors.Join(drainErr, statusErr)
}

func readProtocolFrame(ctx context.Context, conn *websocket.Conn) (contractv1.Frame, error) {
	messageType, payload, err := conn.Read(ctx)
	if err != nil {
		if websocket.CloseStatus(err) == websocket.StatusMessageTooBig {
			return contractv1.Frame{}, closeViolation(websocket.StatusMessageTooBig, "frame exceeds limit", err)
		}
		return contractv1.Frame{}, err
	}
	if messageType != websocket.MessageBinary {
		return contractv1.Frame{}, closeViolation(websocket.StatusInvalidFramePayloadData, "invalid frame payload data", errors.New("protocol requires binary websocket messages"))
	}
	frame, err := contractv1.DecodeFrame(payload)
	if err != nil {
		// Framing-layer violations are protocol errors (1002); payload-layer
		// problems are invalid frame payload data (1007)
		// (contracts/v1/tunnel-protocol.md section 11c).
		var frameErr *contractv1.FrameError
		if errors.As(err, &frameErr) {
			return contractv1.Frame{}, closeViolation(websocket.StatusProtocolError, "protocol error", err)
		}
		return contractv1.Frame{}, closeViolation(websocket.StatusInvalidFramePayloadData, "invalid frame payload data", err)
	}
	return frame, nil
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

func (gateway *Gateway) randomBase64URL(size int) (string, error) {
	if gateway.entropy == nil {
		return "", errors.New("crypto entropy source is unavailable")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(gateway.entropy, data); err != nil {
		return "", fmt.Errorf("read crypto entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func (gateway *Gateway) newID(prefix string) (string, error) {
	random, err := gateway.randomBase64URL(12)
	if err != nil {
		return "", err
	}
	return prefix + "-" + random, nil
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

// forwardingHeaders are client-supplied proxy headers. They are never
// forwarded verbatim: an internet client could otherwise spoof the client
// address a tenant application trusts.
var forwardingHeaders = []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Real-Ip"}

// cloneRequestForTunnel builds the tunneled request: hop-by-hop headers and
// every client-supplied forwarding header are removed, the Host is rewritten
// to the canonical metadata hostname routing actually matched, and the
// forwarding headers are re-set from the trusted peer only.
func (gateway *Gateway) cloneRequestForTunnel(request *http.Request, route contractv1.EndpointRouteAssignment) *http.Request {
	cloned := request.Clone(request.Context())
	removeHopByHopHeaders(cloned.Header)
	for _, name := range forwardingHeaders {
		cloned.Header.Del(name)
	}
	cloned.Host = canonicalHostname(route.PublicHostname)
	if cloned.Host == "" {
		cloned.Host = canonicalHostname(request.Host)
	}
	clientAddress := gateway.peerAddress(request)
	cloned.Header.Set("X-Forwarded-For", clientAddress)
	cloned.Header.Set("X-Real-IP", clientAddress)
	cloned.Header.Set("X-Forwarded-Proto", "https")
	cloned.Header.Set("X-Forwarded-Host", cloned.Host)
	cloned.Header.Set("X-Forwarded-Port", "443")
	cloned.Header.Set("Forwarded", fmt.Sprintf("for=%s;proto=https;host=%s", clientAddress, cloned.Host))
	cloned.Close = false
	cloned.TransferEncoding = nil
	cloned.Trailer = nil
	return cloned
}

// peerAddress returns the trusted client address of a request: the immediate
// peer, or the edge-supplied client hop when (and only when) that peer is a
// configured trusted proxy.
func (gateway *Gateway) peerAddress(request *http.Request) string {
	return peerAddressOf(request, gateway.trustedProxyIPs)
}

func peerAddressOf(request *http.Request, trustedProxyIPs []net.IPNet) string {
	peer := remoteIP(request.RemoteAddr)
	if peer != nil && ipInAny(peer, trustedProxyIPs) {
		if client, ok := lastForwardedFor(request.Header); ok {
			return client.String()
		}
	}
	if peer == nil {
		return "unknown"
	}
	return peer.String()
}

func remoteIP(remoteAddr string) net.IP {
	if remoteAddr == "" {
		return nil
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(remoteAddr)
}

func ipInAny(ip net.IP, nets []net.IPNet) bool {
	for i := range nets {
		if nets[i].Contains(ip) {
			return true
		}
	}
	return false
}

// lastForwardedFor returns the last hop of X-Forwarded-For when it is a valid
// IP address. A trusted edge appends the address it observed, so the last
// element is the only one the edge itself vouches for.
func lastForwardedFor(header http.Header) (net.IP, bool) {
	values := header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return nil, false
	}
	combined := strings.Join(values, ",")
	parts := strings.Split(combined, ",")
	ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1]))
	if ip == nil {
		return nil, false
	}
	return ip, true
}

// parseTrustedProxyPeers parses the configured trusted-proxy list into CIDRs.
// A malformed entry is a startup error rather than a silently ignored one: an
// operator that believed a proxy was trusted must not keep running with a
// weaker (or different) trust set than declared.
func parseTrustedProxyPeers(entries []string) ([]net.IPNet, error) {
	parsed := make([]net.IPNet, 0, len(entries))
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		if ip := net.ParseIP(trimmed); ip != nil {
			bits := 128
			if ip.To4() != nil {
				ip = ip.To4()
				bits = 32
			}
			parsed = append(parsed, net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, network, err := net.ParseCIDR(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy %q: %w", entry, err)
		}
		parsed = append(parsed, *network)
	}
	return parsed, nil
}

// responsePhase bounds the tunneled-response phase by inactivity: every byte
// forwarded in either direction re-arms it, so a stalled Agent is bounded even
// while the public client stays connected, and a progressing transfer of any
// size is never cut off by a total-duration deadline.
type responsePhase struct {
	timer   *time.Timer
	timeout time.Duration
}

func newResponsePhase(timeout time.Duration, cancel context.CancelFunc) *responsePhase {
	return &responsePhase{timer: time.AfterFunc(timeout, cancel), timeout: timeout}
}

func (phase *responsePhase) progress() {
	if phase != nil && phase.timer != nil {
		phase.timer.Reset(phase.timeout)
	}
}

func (phase *responsePhase) stop() {
	if phase != nil && phase.timer != nil {
		phase.timer.Stop()
	}
}

// progressReader re-arms the response-phase deadline when the tunnel delivers
// bytes; a read is otherwise bounded by the stream's own context.
type progressReader struct {
	reader io.Reader
	phase  *responsePhase
}

func (reader *progressReader) Read(data []byte) (int, error) {
	n, err := reader.reader.Read(data)
	if n > 0 {
		reader.phase.progress()
	}
	return n, err
}

// progressWriter applies a per-chunk write deadline to the public connection
// and re-arms the response-phase deadline when bytes reach the client. The
// server-level whole-response write timeout is disabled in favour of this, so
// a large response is not forced to finish inside a single fixed budget while
// a public client that stops reading is still bounded.
type progressWriter struct {
	writer     io.Writer
	controller *http.ResponseController
	timeout    time.Duration
	phase      *responsePhase
	flush      bool
}

func (writer *progressWriter) Write(data []byte) (int, error) {
	if writer.controller != nil {
		// ErrNotSupported is expected for non-networked writers (test
		// recorders); the phase deadline still bounds the response.
		_ = writer.controller.SetWriteDeadline(time.Now().Add(writer.timeout))
	}
	n, err := writer.writer.Write(data)
	if err == nil && n > 0 && writer.flush && writer.controller != nil {
		if flushErr := writer.controller.Flush(); flushErr != nil && !errors.Is(flushErr, http.ErrNotSupported) {
			err = flushErr
		}
	}
	if n > 0 {
		writer.phase.progress()
	}
	return n, err
}

// idleDeadlineReader bounds each read of the public request body with a fresh
// idle deadline instead of one deadline for the whole request.
type idleDeadlineReader struct {
	reader     io.ReadCloser
	controller *http.ResponseController
	timeout    time.Duration
}

func newIdleDeadlineReader(reader io.ReadCloser, controller *http.ResponseController, timeout time.Duration) io.ReadCloser {
	if reader == nil {
		return nil
	}
	return &idleDeadlineReader{reader: reader, controller: controller, timeout: timeout}
}

func (reader *idleDeadlineReader) Read(data []byte) (int, error) {
	if reader.controller != nil {
		_ = reader.controller.SetReadDeadline(time.Now().Add(reader.timeout))
	}
	return reader.reader.Read(data)
}

func (reader *idleDeadlineReader) Close() error { return reader.reader.Close() }

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

func responseHasBody(response *http.Response) bool {
	return (response.Request == nil || response.Request.Method != http.MethodHead) &&
		response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotModified && response.StatusCode >= 200
}

func copyTunneledResponseBody(writer io.Writer, response *http.Response, limit int64) (int64, bool, error) {
	if !responseHasBody(response) {
		return 0, false, nil
	}
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
		if !writer.budget.TryAcquire(int64(size)) {
			writer.rejected.Add(1)
			return total, errResourceBudget
		}
		err := writer.send(writer.ctx, data[:size])
		writer.budget.Release(int64(size))
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
	// The public listener applies a header-phase deadline only. Request-body
	// reads and response writes are bounded per body chunk by the ingress
	// handler (idle read deadline, per-chunk write deadline, response-phase
	// inactivity deadline). A whole-request ReadTimeout/WriteTimeout would
	// instead impose a hidden throughput floor: 15 s for an 8 MiB body and
	// ~42 s for a 32 MiB response.
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: limits.ReadTimeout,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       limits.IdleTimeout,
		MaxHeaderBytes:    limits.MaxHeaderBytes,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}

// NewOpsHTTPServer returns the plaintext administrative listener for the
// Gateway-local operational endpoints. It must be bound to a non-public
// address: it serves liveness/readiness and aggregate metrics without TLS.
func NewOpsHTTPServer(address string, handler http.Handler, limits Limits) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: limits.ReadTimeout,
		IdleTimeout:       limits.IdleTimeout,
		MaxHeaderBytes:    limits.MaxHeaderBytes,
	}
}
