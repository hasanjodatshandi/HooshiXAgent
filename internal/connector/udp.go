package connector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

const udpFlowQueue = 16

type udpFlow struct {
	packets chan []byte
	cancel  context.CancelFunc
}

// ServeUDP maps each local UDP peer to one bounded, stable tunnel flow.
func ServeUDP(ctx context.Context, listener net.PacketConn, config Config, logger *slog.Logger) error {
	if err := config.Validate(); err != nil {
		return err
	}
	address, ok := listener.LocalAddr().(*net.UDPAddr)
	if !ok || !address.IP.IsLoopback() {
		return errors.New("UDP connector listener must be bound to loopback")
	}
	if logger == nil {
		logger = slog.Default()
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	defer listener.Close()
	go func() { <-runCtx.Done(); _ = listener.Close() }()
	flows := make(map[string]*udpFlow)
	var mu sync.Mutex
	var writeMu sync.Mutex
	buffer := make([]byte, contractv1.MaxUDPDatagram+1)
	for {
		n, peer, err := listener.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read local UDP datagram: %w", err)
		}
		udpPeer, ok := peer.(*net.UDPAddr)
		if !ok || !udpPeer.IP.IsLoopback() || n > contractv1.MaxUDPDatagram {
			continue
		}
		key := peer.String()
		mu.Lock()
		flow := flows[key]
		if flow == nil {
			if len(flows) >= config.MaxConnections {
				mu.Unlock()
				continue
			}
			flowCtx, cancel := context.WithCancel(runCtx)
			flow = &udpFlow{packets: make(chan []byte, udpFlowQueue), cancel: cancel}
			flows[key] = flow
			go func() {
				defer cancel()
				if err := proxyUDP(flowCtx, listener, peer, flow.packets, config, &writeMu); err != nil && runCtx.Err() == nil {
					logger.Warn("connector UDP flow ended", "error", err)
				}
				mu.Lock()
				if flows[key] == flow {
					delete(flows, key)
				}
				mu.Unlock()
			}()
		}
		packet := append([]byte(nil), buffer[:n]...)
		select {
		case flow.packets <- packet:
		default: // bounded UDP congestion drops a datagram, not the shared listener
		}
		mu.Unlock()
	}
}

func proxyUDP(parent context.Context, local net.PacketConn, peer net.Addr, packets <-chan []byte, config Config, writeMu *sync.Mutex) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	lastActivity := atomic.Int64{}
	lastActivity.Store(time.Now().UnixNano())
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, lastActivity.Load())) >= config.IdleTimeout {
					cancel()
					return
				}
			}
		}
	}()
	headers := http.Header{
		"Authorization":      []string{"Bearer " + config.Token},
		"X-Hooshix-Grant-ID": []string{config.GrantID},
		"X-Hooshix-Token-ID": []string{config.TokenID},
		"X-Hooshix-Protocol": []string{"udp"},
	}
	dialCtx, dialCancel := context.WithTimeout(ctx, config.DialTimeout)
	remote, response, err := websocket.Dial(dialCtx, config.GatewayURL, &websocket.DialOptions{
		HTTPHeader: headers, HTTPClient: config.HTTPClient, CompressionMode: websocket.CompressionDisabled,
	})
	dialCancel()
	if err != nil {
		if response != nil {
			return fmt.Errorf("connector gateway rejected UDP flow: HTTP %d", response.StatusCode)
		}
		return fmt.Errorf("dial UDP connector gateway: %w", err)
	}
	defer remote.CloseNow()
	remote.SetReadLimit(contractv1.MaxUDPDatagram + 1)
	writerDone := make(chan error, 1)
	go func() {
		writeErr := writeUDPToGateway(ctx, remote, packets, config.WriteTimeout, &lastActivity)
		if writeErr != nil {
			cancel()
		}
		writerDone <- writeErr
	}()
	readErr := readUDPFromGateway(ctx, remote, local, peer, config.WriteTimeout, &lastActivity, writeMu)
	wasCanceled := ctx.Err() != nil
	cancel()
	writeErr := <-writerDone
	_ = remote.Close(websocket.StatusNormalClosure, "connector UDP flow complete")
	if readErr != nil && !wasCanceled {
		return readErr
	}
	return writeErr
}

func writeUDPToGateway(ctx context.Context, remote *websocket.Conn, packets <-chan []byte, timeout time.Duration, lastActivity *atomic.Int64) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case packet := <-packets:
			payload := make([]byte, len(packet)+1)
			payload[0] = dataFrame
			copy(payload[1:], packet)
			writeCtx, cancel := context.WithTimeout(ctx, timeout)
			err := remote.Write(writeCtx, websocket.MessageBinary, payload)
			cancel()
			if err != nil {
				return err
			}
			lastActivity.Store(time.Now().UnixNano())
		}
	}
}

func readUDPFromGateway(ctx context.Context, remote *websocket.Conn, local net.PacketConn, peer net.Addr, timeout time.Duration, lastActivity *atomic.Int64, writeMu *sync.Mutex) error {
	for {
		messageType, payload, err := remote.Read(ctx)
		if err != nil {
			return err
		}
		if messageType != websocket.MessageBinary || len(payload) == 0 || payload[0] != dataFrame || len(payload)-1 > contractv1.MaxUDPDatagram {
			return errors.New("invalid gateway UDP datagram")
		}
		writeMu.Lock()
		if err := local.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			writeMu.Unlock()
			return err
		}
		n, err := local.WriteTo(payload[1:], peer)
		writeMu.Unlock()
		if err != nil {
			return err
		}
		if n != len(payload)-1 {
			return errors.New("short UDP datagram write")
		}
		lastActivity.Store(time.Now().UnixNano())
	}
}
