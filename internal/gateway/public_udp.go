package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
	contractv2 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv2"
)

// PublicUDPConfig uses the same reserved port range and reconciliation policy as public TCP.
type PublicUDPConfig = PublicTCPConfig

type PublicUDPManager struct {
	gateway   *Gateway
	metadata  PublicUDPMetadata
	config    PublicUDPConfig
	logger    *slog.Logger
	mu        sync.Mutex
	listeners map[int]*publicUDPListener
	closed    bool
	wg        sync.WaitGroup
}

type publicUDPListener struct {
	endpoint contractv2.ServiceEndpoint
	conn     net.PacketConn
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	flows    map[string]*publicUDPFlow
}

type publicUDPFlow struct {
	packets chan []byte
	peer    net.Addr
	credit  atomic.Int64
}

const maxUDPResponseCredit = 1 << 20

func (flow *publicUDPFlow) addRequestCredit(size int) {
	for {
		current := flow.credit.Load()
		next := min(current+3*int64(size), maxUDPResponseCredit)
		if flow.credit.CompareAndSwap(current, next) {
			return
		}
	}
}

func (flow *publicUDPFlow) spendResponseCredit(size int) bool {
	for {
		current := flow.credit.Load()
		if current < int64(size) {
			return false
		}
		if flow.credit.CompareAndSwap(current, current-int64(size)) {
			return true
		}
	}
}

func NewPublicUDPManager(gateway *Gateway, metadata MetadataSource, config PublicUDPConfig, logger *slog.Logger) (*PublicUDPManager, error) {
	publicMetadata, ok := metadata.(PublicUDPMetadata)
	if !ok {
		return nil, errors.New("metadata source does not support public UDP endpoints")
	}
	if gateway == nil || config.BindHost == "" || config.PortMin < 1024 || config.PortMax > 65535 || config.PortMin > config.PortMax || config.ReconcileInterval <= 0 {
		return nil, errors.New("invalid public UDP configuration")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &PublicUDPManager{gateway: gateway, metadata: publicMetadata, config: config, logger: logger, listeners: make(map[int]*publicUDPListener)}, nil
}

func (manager *PublicUDPManager) Run(ctx context.Context) error {
	if err := manager.reconcile(ctx); err != nil {
		manager.logger.Warn("public UDP metadata unavailable", "error", err)
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
				manager.logger.Warn("public UDP metadata unavailable", "error", err)
			}
		}
	}
}

func (manager *PublicUDPManager) Close() {
	manager.mu.Lock()
	if !manager.closed {
		manager.closed = true
		manager.closeAllLocked()
	}
	manager.mu.Unlock()
	manager.wg.Wait()
}

func (manager *PublicUDPManager) closeAllLocked() {
	for port, active := range manager.listeners {
		active.cancel()
		_ = active.conn.Close()
		delete(manager.listeners, port)
	}
}

func (manager *PublicUDPManager) reconcile(ctx context.Context) error {
	endpoints, err := manager.metadata.PublicUDPEndpoints(ctx, time.Now().UTC())
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed {
		return nil
	}
	if err != nil {
		manager.closeAllLocked()
		return err
	}
	wanted := make(map[int]contractv2.ServiceEndpoint, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.Protocol == contractv2.ProtocolUDP && endpoint.PublicPort >= manager.config.PortMin && endpoint.PublicPort <= manager.config.PortMax {
			wanted[endpoint.PublicPort] = endpoint
		}
	}
	for port, active := range manager.listeners {
		endpoint, keep := wanted[port]
		if keep && reflect.DeepEqual(endpoint, active.endpoint) {
			delete(wanted, port)
			continue
		}
		active.cancel()
		_ = active.conn.Close()
		delete(manager.listeners, port)
	}
	for port, endpoint := range wanted {
		conn, err := net.ListenPacket("udp4", net.JoinHostPort(manager.config.BindHost, strconv.Itoa(port)))
		if err != nil {
			manager.logger.Error("public UDP listener failed", "port", port, "error", err)
			continue
		}
		listenerCtx, cancel := context.WithCancel(ctx)
		active := &publicUDPListener{endpoint: endpoint, conn: conn, ctx: listenerCtx, cancel: cancel, flows: make(map[string]*publicUDPFlow)}
		manager.listeners[port] = active
		manager.wg.Add(1)
		go manager.read(active)
		manager.logger.Info("public UDP listener active", "port", port, "endpoint_id", endpoint.EndpointID)
	}
	return nil
}

func (manager *PublicUDPManager) read(active *publicUDPListener) {
	defer manager.wg.Done()
	buffer := make([]byte, contractv1.MaxUDPDatagram+1)
	for {
		n, peer, err := active.conn.ReadFrom(buffer)
		if err != nil {
			if active.ctx.Err() == nil {
				manager.logger.Warn("public UDP read failed", "port", active.endpoint.PublicPort, "error", err)
			}
			return
		}
		if n > contractv1.MaxUDPDatagram || manager.gateway.draining.Load() {
			continue
		}
		udpPeer, ok := peer.(*net.UDPAddr)
		if !ok || !sourceAllowed(udpPeer.IP, active.endpoint.AllowedSourceCIDRs) {
			continue
		}
		key := peer.String()
		active.mu.Lock()
		flow := active.flows[key]
		if flow == nil {
			if len(active.flows) >= cap(manager.gateway.resources.ingressSlots) {
				manager.gateway.resources.ingressRejects.Add(1)
				active.mu.Unlock()
				continue
			}
			now := time.Now()
			if !manager.gateway.resources.preAuthRate.Allow("public-udp:"+udpPeer.IP.String(), now) || !manager.gateway.resources.ingressRate.Allow(now) {
				manager.gateway.resources.ingressRejects.Add(1)
				active.mu.Unlock()
				continue
			}
			flow = &publicUDPFlow{packets: make(chan []byte, 16), peer: peer}
			flow.credit.Store(contractv1.MaxUDPDatagram)
			active.flows[key] = flow
			manager.wg.Add(1)
			go func() {
				defer manager.wg.Done()
				manager.serveFlow(active, flow)
				active.mu.Lock()
				if active.flows[key] == flow {
					delete(active.flows, key)
				}
				active.mu.Unlock()
			}()
		}
		packet := append([]byte(nil), buffer[:n]...)
		select {
		case flow.packets <- packet:
		default:
			manager.gateway.resources.ingressRejects.Add(1)
		}
		active.mu.Unlock()
	}
}

func (manager *PublicUDPManager) serveFlow(active *publicUDPListener, flow *publicUDPFlow) {
	now := time.Now()
	resources := &manager.gateway.resources
	endpoint := active.endpoint
	if resources.ingressRouteAdmission.TryAcquire(endpoint.EndpointID, now) != admissionAccepted {
		return
	}
	defer resources.ingressRouteAdmission.Release(endpoint.EndpointID)
	if resources.ingressDeviceAdmission.TryAcquire(endpoint.OwnerDeviceID, now) != admissionAccepted {
		return
	}
	defer resources.ingressDeviceAdmission.Release(endpoint.OwnerDeviceID)
	select {
	case resources.ingressSlots <- struct{}{}:
		defer func() { <-resources.ingressSlots }()
	default:
		resources.ingressRejects.Add(1)
		return
	}
	sess := manager.gateway.sessionForDevice(endpoint.OwnerDeviceID)
	if sess == nil {
		return
	}
	ctx, cancel := context.WithCancel(active.ctx)
	defer cancel()
	stream, err := sess.openStreamTarget(ctx, endpoint.EndpointID, endpoint.EndpointID, endpoint.LocalEndpointID, "udp")
	if err != nil {
		return
	}
	defer stream.discardRetained()
	defer sess.closeStream(stream.id, "cancelled")
	go func() { <-ctx.Done(); sess.closeStream(stream.id, "cancelled") }()
	lastActivity := atomic.Int64{}
	lastActivity.Store(time.Now().UnixNano())
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			packet, err := stream.ReadDatagram()
			if err != nil {
				cancel()
				return
			}
			if !flow.spendResponseCredit(len(packet)) {
				resources.ingressRejects.Add(1)
				continue
			}
			written, err := active.conn.WriteTo(packet, flow.peer)
			if err != nil || written != len(packet) {
				cancel()
				return
			}
			resources.publicBytes.Add(uint64(written))
			lastActivity.Store(time.Now().UnixNano())
		}
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			<-readerDone
			return
		case <-ticker.C:
			if time.Since(time.Unix(0, lastActivity.Load())) >= manager.gateway.limits.IdleTimeout {
				cancel()
			}
		case packet := <-flow.packets:
			if err := sess.sendDatagram(ctx, stream.id, packet); err != nil {
				cancel()
				continue
			}
			flow.addRequestCredit(len(packet))
			lastActivity.Store(time.Now().UnixNano())
		}
	}
}
