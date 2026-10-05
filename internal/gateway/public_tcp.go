package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"

	contractv2 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv2"
)

type PublicTCPConfig struct {
	BindHost          string
	PortMin           int
	PortMax           int
	ReconcileInterval time.Duration
}

type PublicTCPManager struct {
	gateway  *Gateway
	metadata PublicTCPMetadata
	config   PublicTCPConfig
	logger   *slog.Logger

	mu        sync.Mutex
	listeners map[int]*publicTCPListener
	closed    bool
	closeDone chan struct{}
	wg        sync.WaitGroup
}

type publicTCPListener struct {
	endpoint contractv2.ServiceEndpoint
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewPublicTCPManager(gateway *Gateway, metadata MetadataSource, config PublicTCPConfig, logger *slog.Logger) (*PublicTCPManager, error) {
	publicMetadata, ok := metadata.(PublicTCPMetadata)
	if !ok {
		return nil, errors.New("metadata source does not support public TCP endpoints")
	}
	if gateway == nil || config.BindHost == "" || config.PortMin < 1024 || config.PortMax > 65535 || config.PortMin > config.PortMax || config.ReconcileInterval <= 0 {
		return nil, errors.New("invalid public TCP configuration")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &PublicTCPManager{gateway: gateway, metadata: publicMetadata, config: config, logger: logger, listeners: make(map[int]*publicTCPListener), closeDone: make(chan struct{})}, nil
}

func (manager *PublicTCPManager) Run(ctx context.Context) error {
	if err := manager.reconcile(ctx); err != nil {
		manager.logger.Warn("public TCP metadata unavailable", "error", err)
	}
	ticker := time.NewTicker(manager.config.ReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			manager.Close()
			return nil
		case <-ticker.C:
			if err := manager.reconcile(ctx); err != nil {
				manager.logger.Warn("public TCP metadata unavailable", "error", err)
			}
		}
	}
}

func (manager *PublicTCPManager) Close() {
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		<-manager.closeDone
		return
	}
	manager.closed = true
	for port, listener := range manager.listeners {
		listener.cancel()
		_ = listener.listener.Close()
		delete(manager.listeners, port)
	}
	manager.mu.Unlock()
	manager.wg.Wait()
	close(manager.closeDone)
}

func (manager *PublicTCPManager) reconcile(ctx context.Context) error {
	endpoints, err := manager.metadata.PublicTCPEndpoints(ctx, time.Now().UTC())
	if err != nil {
		manager.closeAll()
		return err
	}
	wanted := make(map[int]contractv2.ServiceEndpoint, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.Protocol == contractv2.ProtocolTCP && endpoint.PublicPort >= manager.config.PortMin && endpoint.PublicPort <= manager.config.PortMax {
			wanted[endpoint.PublicPort] = endpoint
		}
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed {
		return nil
	}
	for port, active := range manager.listeners {
		endpoint, keep := wanted[port]
		if keep && reflect.DeepEqual(endpoint, active.endpoint) {
			delete(wanted, port)
			continue
		}
		active.cancel()
		_ = active.listener.Close()
		delete(manager.listeners, port)
	}
	for port, endpoint := range wanted {
		listener, err := net.Listen("tcp", net.JoinHostPort(manager.config.BindHost, strconv.Itoa(port)))
		if err != nil {
			manager.logger.Error("public TCP listener failed", "port", port, "endpoint_id", endpoint.EndpointID, "error", err)
			continue
		}
		listenerCtx, cancel := context.WithCancel(ctx)
		active := &publicTCPListener{endpoint: endpoint, listener: listener, ctx: listenerCtx, cancel: cancel}
		manager.listeners[port] = active
		manager.wg.Add(1)
		go manager.accept(active)
		manager.logger.Info("public TCP listener active", "port", port, "endpoint_id", endpoint.EndpointID)
	}
	return nil
}

func (manager *PublicTCPManager) closeAll() {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for port, listener := range manager.listeners {
		listener.cancel()
		_ = listener.listener.Close()
		delete(manager.listeners, port)
	}
}

func (manager *PublicTCPManager) accept(active *publicTCPListener) {
	defer manager.wg.Done()
	for {
		conn, err := active.listener.Accept()
		if err != nil {
			if active.ctx.Err() != nil {
				return
			}
			manager.logger.Warn("public TCP accept failed", "port", active.endpoint.PublicPort, "error", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		manager.mu.Lock()
		if manager.closed || active.ctx.Err() != nil {
			manager.mu.Unlock()
			_ = conn.Close()
			return
		}
		manager.wg.Add(1)
		manager.mu.Unlock()
		go func() {
			defer manager.wg.Done()
			manager.handleConnection(active, conn)
		}()
	}
}

func (manager *PublicTCPManager) handleConnection(active *publicTCPListener, conn net.Conn) {
	defer conn.Close()
	if active.ctx.Err() != nil {
		return
	}
	ip := remoteIP(conn.RemoteAddr().String())
	if ip == nil || !sourceAllowed(ip, active.endpoint.AllowedSourceCIDRs) || manager.gateway.draining.Load() {
		return
	}
	now := time.Now()
	peerKey := "public-tcp:" + ip.String()
	if !manager.gateway.resources.preAuthRate.Allow(peerKey, now) || !manager.gateway.resources.ingressRate.Allow(now) {
		manager.gateway.resources.ingressRejects.Add(1)
		return
	}
	if manager.gateway.resources.ingressRouteAdmission.TryAcquire(active.endpoint.EndpointID, now) != admissionAccepted {
		return
	}
	defer manager.gateway.resources.ingressRouteAdmission.Release(active.endpoint.EndpointID)
	if manager.gateway.resources.ingressDeviceAdmission.TryAcquire(active.endpoint.OwnerDeviceID, now) != admissionAccepted {
		return
	}
	defer manager.gateway.resources.ingressDeviceAdmission.Release(active.endpoint.OwnerDeviceID)
	select {
	case manager.gateway.resources.ingressSlots <- struct{}{}:
		defer func() { <-manager.gateway.resources.ingressSlots }()
	default:
		manager.gateway.resources.ingressRejects.Add(1)
		return
	}

	sess := manager.gateway.sessionForDevice(active.endpoint.OwnerDeviceID)
	if sess == nil || !sess.supportsHalfClose {
		return
	}
	ctx, cancel := context.WithCancel(active.ctx)
	defer cancel()
	phase := newResponsePhase(manager.gateway.limits.ResponsePhaseTimeout, cancel)
	defer phase.stop()
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	stream, err := sess.openStreamTarget(ctx, active.endpoint.EndpointID, active.endpoint.EndpointID, active.endpoint.LocalEndpointID, "tcp")
	if err != nil {
		return
	}
	defer stream.discardRetained()
	defer sess.closeStream(stream.id, "cancelled")

	toClient := make(chan error, 1)
	go func() {
		err := manager.writePublicTCP(ctx, conn, stream, phase)
		if err != nil {
			cancel()
		}
		toClient <- err
	}()
	readErr := manager.readPublicTCP(ctx, conn, sess, stream.id, phase)
	if readErr != nil {
		cancel()
	}
	<-toClient
}

func (manager *PublicTCPManager) readPublicTCP(ctx context.Context, conn net.Conn, sess *session, streamID uint32, phase *responsePhase) error {
	buffer := make([]byte, 32<<10)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(manager.gateway.limits.IdleTimeout))
		n, err := conn.Read(buffer)
		if n > 0 {
			phase.progress()
			if sendErr := sess.sendBytes(ctx, streamID, buffer[:n]); sendErr != nil {
				return sendErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return sess.halfCloseStream(streamID)
			}
			return err
		}
	}
}

func (manager *PublicTCPManager) writePublicTCP(ctx context.Context, conn net.Conn, stream *stream, phase *responsePhase) error {
	buffer := make([]byte, 32<<10)
	for {
		n, err := stream.Read(buffer)
		if n > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(manager.gateway.limits.WriteTimeout))
			for remaining := buffer[:n]; len(remaining) > 0; {
				written, writeErr := conn.Write(remaining)
				if written > 0 {
					phase.progress()
					manager.gateway.resources.publicBytes.Add(uint64(written))
					remaining = remaining[written:]
				}
				if writeErr != nil {
					return writeErr
				}
				if written == 0 {
					return io.ErrShortWrite
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if tcp, ok := conn.(*net.TCPConn); ok {
					return tcp.CloseWrite()
				}
				return nil
			}
			return fmt.Errorf("read public TCP stream: %w", err)
		}
	}
}

func sourceAllowed(ip net.IP, cidrs []string) bool {
	for _, raw := range cidrs {
		_, network, err := net.ParseCIDR(raw)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
