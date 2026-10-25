package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/coder/websocket"
	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
	contractv2 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv2"
)

const (
	connectorDataFrame      byte = 0
	connectorHalfCloseFrame byte = 1
)

func (gateway *Gateway) handleConnector(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || gateway.draining.Load() {
		http.Error(response, "connector unavailable", http.StatusServiceUnavailable)
		return
	}
	if !gateway.resources.preAuthRate.Allow("connector:"+gateway.peerAddress(request), time.Now()) {
		http.Error(response, "connector authorization failed", http.StatusTooManyRequests)
		return
	}
	metadata, ok := gateway.metadata.(PrivateEndpointMetadata)
	if !ok {
		http.Error(response, "connector unavailable", http.StatusServiceUnavailable)
		return
	}
	grantID := request.Header.Get("X-Hooshix-Grant-ID")
	tokenID := request.Header.Get("X-Hooshix-Token-ID")
	token, ok := bearerToken(request.Header.Get("Authorization"))
	if !ok {
		http.Error(response, "connector authorization failed", http.StatusUnauthorized)
		return
	}
	grant, endpoint, err := authorizeConnector(request.Context(), metadata, grantID, tokenID, token, time.Now().UTC())
	if err != nil {
		http.Error(response, "connector authorization failed", http.StatusUnauthorized)
		return
	}
	requestedProtocol := request.Header.Get("X-Hooshix-Protocol")
	if (endpoint.Protocol == contractv2.ProtocolUDP && requestedProtocol != "udp") ||
		(endpoint.Protocol == contractv2.ProtocolTCP && requestedProtocol != "" && requestedProtocol != "tcp") {
		http.Error(response, "connector authorization failed", http.StatusUnauthorized)
		return
	}
	sess := gateway.sessionForDevice(endpoint.OwnerDeviceID)
	if sess == nil || (endpoint.Protocol == contractv2.ProtocolTCP && !sess.supportsHalfClose) {
		http.Error(response, "connector unavailable", http.StatusServiceUnavailable)
		return
	}
	if !gateway.acquireConnectorGrant(grant.GrantID, grant.MaxConnections) {
		http.Error(response, "connector capacity reached", http.StatusServiceUnavailable)
		return
	}
	defer gateway.releaseConnectorGrant(grant.GrantID)

	now := time.Now()
	routeAdmission := gateway.resources.ingressRouteAdmission.TryAcquire(endpoint.EndpointID, now)
	if routeAdmission != admissionAccepted {
		status := http.StatusServiceUnavailable
		message := "connector capacity reached"
		if routeAdmission == admissionRejectedRate {
			status = http.StatusTooManyRequests
			message = "connector rate limit exceeded"
		}
		http.Error(response, message, status)
		return
	}
	defer gateway.resources.ingressRouteAdmission.Release(endpoint.EndpointID)

	deviceAdmission := gateway.resources.ingressDeviceAdmission.TryAcquire(endpoint.OwnerDeviceID, now)
	if deviceAdmission != admissionAccepted {
		status := http.StatusServiceUnavailable
		message := "connector capacity reached"
		if deviceAdmission == admissionRejectedRate {
			status = http.StatusTooManyRequests
			message = "connector rate limit exceeded"
		}
		http.Error(response, message, status)
		return
	}
	defer gateway.resources.ingressDeviceAdmission.Release(endpoint.OwnerDeviceID)
	if !gateway.resources.ingressRate.Allow(now) {
		http.Error(response, "connector rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	select {
	case gateway.resources.ingressSlots <- struct{}{}:
		defer func() { <-gateway.resources.ingressSlots }()
	default:
		gateway.resources.ingressRejects.Add(1)
		http.Error(response, "connector capacity reached", http.StatusServiceUnavailable)
		return
	}

	conn, err := websocket.Accept(response, request, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	conn.SetReadLimit(int64(contractv1.MaxDataPayload + 1))
	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	go gateway.monitorConnectorAuthorization(ctx, cancel, metadata, grant, endpoint, token)
	var stream *stream
	if endpoint.Protocol == contractv2.ProtocolUDP {
		stream, err = sess.openPrivateUDPFlow(ctx, endpoint.EndpointID, grant.GrantID, endpoint.LocalEndpointID)
	} else {
		stream, err = sess.openPrivateStream(ctx, endpoint.EndpointID, grant.GrantID, endpoint.LocalEndpointID)
	}
	if err != nil {
		_ = conn.Close(websocket.StatusTryAgainLater, "private stream unavailable")
		return
	}
	defer stream.discardRetained()
	defer sess.closeStream(stream.id, "cancelled")
	audit := connectorFlowAudit{
		gateway: gateway, grantID: grant.GrantID, endpointID: endpoint.EndpointID,
		deviceID: sess.deviceID, protocol: string(endpoint.Protocol), streamID: stream.id,
		started: time.Now(),
	}
	audit.open()
	if endpoint.Protocol == contractv2.ProtocolUDP {
		toConnector := make(chan error, 1)
		go func() { toConnector <- gateway.writeConnectorUDP(ctx, conn, stream) }()
		readErr := gateway.readConnectorUDP(ctx, conn, sess, stream.id)
		cancel()
		writeErr := <-toConnector
		_ = conn.Close(websocket.StatusNormalClosure, "connector UDP flow complete")
		audit.finish(firstConnectorError(readErr, writeErr))
		return
	}

	toConnector := make(chan error, 1)
	go func() { toConnector <- gateway.writeConnector(ctx, conn, stream) }()
	readErr := gateway.readConnector(ctx, conn, sess, stream.id)
	writeErr := error(nil)
	if readErr == nil {
		select {
		case writeErr = <-toConnector:
		case <-time.After(gateway.limits.IdleTimeout):
			// The read side finished but the writer never came back, which is a
			// stalled gateway leg, not a completed flow. Saying so is the only way
			// this shows up in the journal at all.
			writeErr = errors.New("connector writer still open after the idle timeout")
		}
	} else {
		cancel()
		writeErr = <-toConnector
	}
	_ = conn.Close(websocket.StatusNormalClosure, "connector flow complete")
	audit.finish(firstConnectorError(readErr, writeErr))
}

// connectorFlowAudit is the Gateway-side record of one tunnelled flow. During an
// RDP incident the question is whether the flow ever reached the Gateway, how
// long it carried data, and which side ended it; before this pair the Gateway
// journal was silent about connector traffic. Grant and endpoint IDs identify a
// purpose, and the bearer token never reaches a log line.
type connectorFlowAudit struct {
	gateway    *Gateway
	grantID    string
	endpointID string
	deviceID   string
	protocol   string
	streamID   uint32
	started    time.Time
}

func (audit connectorFlowAudit) open() {
	audit.gateway.logger.Info("connector flow open",
		"grant_id", audit.grantID, "endpoint_id", audit.endpointID, "device_id", audit.deviceID,
		"protocol", audit.protocol, "stream_id", audit.streamID,
	)
}

func (audit connectorFlowAudit) finish(cause error) {
	fields := []any{
		"grant_id", audit.grantID, "endpoint_id", audit.endpointID, "device_id", audit.deviceID,
		"protocol", audit.protocol, "stream_id", audit.streamID,
		"duration", time.Since(audit.started).Round(time.Millisecond),
	}
	if endedNormally(cause) {
		audit.gateway.logger.Info("connector flow closed", fields...)
		return
	}
	audit.gateway.logger.Warn("connector flow closed", append(fields, "error", cause)...)
}

// endedNormally separates a flow that finished its purpose from one that broke:
// a public client hanging up arrives as a normal close or a cancellation, and
// only that.
func endedNormally(cause error) bool {
	if cause == nil || errors.Is(cause, io.EOF) || errors.Is(cause, context.Canceled) {
		return true
	}
	return websocket.CloseStatus(cause) == websocket.StatusNormalClosure
}

// firstConnectorError reports the cause a two-sided copy ended with. The read
// side is the honest one: a write failure usually follows the peer going away
// rather than causing it.
func firstConnectorError(readErr, writeErr error) error {
	if readErr != nil {
		return readErr
	}
	return writeErr
}

func (gateway *Gateway) readConnectorUDP(parent context.Context, conn *websocket.Conn, sess *session, streamID uint32) error {
	for {
		ctx, cancel := context.WithTimeout(parent, gateway.limits.IdleTimeout)
		messageType, payload, err := conn.Read(ctx)
		cancel()
		if err != nil {
			return err
		}
		if messageType != websocket.MessageBinary || len(payload) == 0 || payload[0] != connectorDataFrame || len(payload)-1 > contractv1.MaxUDPDatagram {
			return errors.New("invalid connector UDP datagram")
		}
		if err := sess.sendDatagram(parent, streamID, payload[1:]); err != nil {
			return err
		}
	}
}

func (gateway *Gateway) writeConnectorUDP(parent context.Context, conn *websocket.Conn, stream *stream) error {
	for {
		packet, err := stream.ReadDatagram()
		if err != nil {
			return err
		}
		payload := make([]byte, len(packet)+1)
		payload[0] = connectorDataFrame
		copy(payload[1:], packet)
		ctx, cancel := context.WithTimeout(parent, gateway.limits.WriteTimeout)
		writeErr := conn.Write(ctx, websocket.MessageBinary, payload)
		cancel()
		if writeErr != nil {
			return writeErr
		}
	}
}

// monitorConnectorAuthorization bounds the lifetime of already-open flows.
// A revoked/expired grant or a changed endpoint mapping cancels the stream on
// the next metadata refresh instead of authorizing it until TCP disconnect.
func (gateway *Gateway) monitorConnectorAuthorization(
	ctx context.Context,
	cancel context.CancelFunc,
	metadata PrivateEndpointMetadata,
	grant contractv2.ConnectorGrant,
	endpoint contractv2.ServiceEndpoint,
	token string,
) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case at := <-ticker.C:
			checkCtx, checkCancel := context.WithTimeout(ctx, gateway.limits.HandshakeTimeout)
			currentGrant, currentEndpoint, err := authorizeConnector(checkCtx, metadata, grant.GrantID, grant.TokenID, token, at.UTC())
			checkCancel()
			if err != nil || currentGrant != grant || !reflect.DeepEqual(currentEndpoint, endpoint) {
				cancel()
				return
			}
		}
	}
}

func (gateway *Gateway) readConnector(parent context.Context, conn *websocket.Conn, sess *session, streamID uint32) error {
	for {
		ctx, cancel := context.WithTimeout(parent, gateway.limits.IdleTimeout)
		messageType, payload, err := conn.Read(ctx)
		cancel()
		if err != nil {
			return err
		}
		if messageType != websocket.MessageBinary || len(payload) == 0 {
			return errors.New("invalid connector frame")
		}
		switch payload[0] {
		case connectorDataFrame:
			if len(payload) == 1 {
				continue
			}
			if err := sess.sendBytes(parent, streamID, payload[1:]); err != nil {
				return err
			}
		case connectorHalfCloseFrame:
			if len(payload) != 1 {
				return errors.New("invalid connector half-close frame")
			}
			return sess.halfCloseStream(streamID)
		default:
			return errors.New("unknown connector frame")
		}
	}
}

func (gateway *Gateway) writeConnector(parent context.Context, conn *websocket.Conn, stream *stream) error {
	buffer := make([]byte, 32<<10)
	for {
		n, err := stream.Read(buffer)
		if n > 0 {
			payload := make([]byte, n+1)
			payload[0] = connectorDataFrame
			copy(payload[1:], buffer[:n])
			ctx, cancel := context.WithTimeout(parent, gateway.limits.WriteTimeout)
			writeErr := conn.Write(ctx, websocket.MessageBinary, payload)
			cancel()
			if writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				ctx, cancel := context.WithTimeout(parent, gateway.limits.WriteTimeout)
				writeErr := conn.Write(ctx, websocket.MessageBinary, []byte{connectorHalfCloseFrame})
				cancel()
				return writeErr
			}
			return err
		}
	}
}

func bearerToken(value string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(value, prefix) {
		return "", false
	}
	token := strings.TrimPrefix(value, prefix)
	return token, len(token) >= 32 && len(token) <= 512 && !strings.ContainsAny(token, " \t\r\n")
}

func (gateway *Gateway) acquireConnectorGrant(grantID string, limit int) bool {
	gateway.connectorMu.Lock()
	defer gateway.connectorMu.Unlock()
	if gateway.connectorFlows[grantID] >= limit {
		return false
	}
	gateway.connectorFlows[grantID]++
	return true
}

func (gateway *Gateway) releaseConnectorGrant(grantID string) {
	gateway.connectorMu.Lock()
	defer gateway.connectorMu.Unlock()
	if gateway.connectorFlows[grantID] <= 1 {
		delete(gateway.connectorFlows, grantID)
		return
	}
	gateway.connectorFlows[grantID]--
}
