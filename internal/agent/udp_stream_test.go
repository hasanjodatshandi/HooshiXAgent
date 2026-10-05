package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

func TestUDPStreamPreservesDatagramBoundaries(t *testing.T) {
	local, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	go func() {
		buffer := make([]byte, 32)
		for range 2 {
			n, peer, readErr := local.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			_, _ = local.WriteTo(bytes.ToUpper(buffer[:n]), peer)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limits := DefaultLimits()
	limits.IdleTimeout = time.Second
	frames := make(chan contractv1.Frame, 8)
	sess := &agentSession{
		limits: limits, logger: quietAgentLogger(), streams: make(map[uint32]*agentStream),
		closed: make(chan struct{}), controlWrites: make(chan agentWriteRequest, 32), dataWrites: make(chan agentWriteRequest, 2),
		writeMessage: func(_ context.Context, data []byte) error {
			frame, decodeErr := contractv1.DecodeFrame(data)
			if decodeErr == nil {
				frames <- frame
			}
			return decodeErr
		},
	}
	go sess.writeLoop()
	defer sess.shutdown()
	stream := &agentStream{
		id: 1, endpoint: Endpoint{ID: "udp-1", Target: local.LocalAddr().String(), Protocol: "udp"},
		incoming: make(chan agentQueuedPayload, 4), space: make(chan struct{}, 1), ctx: ctx, cancel: cancel,
		streamBudget: newAgentByteBudget(4096), sessionBudget: newAgentByteBudget(4096),
		logger: quietAgentLogger(), mode: "udp", peerHalfClose: make(chan struct{}),
	}
	sess.streams[1] = stream
	go sess.serveUDPStream(stream)
	for _, packet := range [][]byte{[]byte("a"), []byte("bc")} {
		if !stream.enqueue(packet) {
			t.Fatal("failed to queue UDP datagram")
		}
	}
	for _, want := range []string{"A", "BC"} {
		select {
		case frame := <-frames:
			if frame.Kind != contractv1.KindData || string(frame.Payload) != want {
				t.Fatalf("got frame kind=%d payload=%q; want one %q datagram", frame.Kind, frame.Payload, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for UDP datagram")
		}
	}
	cancel()
}

func TestUDPLocalTargetAndProtocolValidation(t *testing.T) {
	if _, err := DialLocalUDPTarget(context.Background(), "192.0.2.1:53", time.Second); err == nil {
		t.Fatal("non-loopback UDP target was accepted")
	}
	config := Config{Version: ConfigVersion, GatewayURL: "wss://example.com/agent/v1/connect", DeviceID: "device-1", AuthorizationID: "auth-1", TokenID: "token-1", UpdateChannel: "stable"}
	config.Endpoints = []Endpoint{{ID: "udp-1", Target: "127.0.0.1:53", Protocol: "udp"}}
	if err := config.ValidateRuntime(); err != nil {
		t.Fatalf("valid UDP endpoint: %v", err)
	}
	config.Endpoints[0].Protocol = "quic"
	if err := config.ValidateRuntime(); err == nil {
		t.Fatal("unknown local protocol was accepted")
	}
	if maxUDPDatagram > contractv1.MaxDataPayload {
		t.Fatalf("UDP datagram limit %d exceeds frame payload limit %d", maxUDPDatagram, contractv1.MaxDataPayload)
	}
}

func TestUDPStreamOpenRejectsProtocolMismatch(t *testing.T) {
	controls := make(chan contractv1.Frame, 1)
	sess := &agentSession{
		config: Config{Endpoints: []Endpoint{{ID: "local-1", Target: "127.0.0.1:53"}}},
		limits: DefaultLimits(), logger: quietAgentLogger(), streams: make(map[uint32]*agentStream),
		closed: make(chan struct{}), controlWrites: make(chan agentWriteRequest, 32), dataWrites: make(chan agentWriteRequest, 2),
		writeMessage: func(_ context.Context, data []byte) error {
			frame, err := contractv1.DecodeFrame(data)
			if err == nil {
				controls <- frame
			}
			return err
		},
	}
	go sess.writeLoop()
	defer sess.shutdown()
	payload, err := json.Marshal(contractv1.StreamOpen{
		ContractVersion: contractv1.ProtocolVersion, MessageType: "stream_open", EndpointID: "endpoint-1",
		AssignmentID: "assign-1", LocalEndpointID: "local-1", RequestID: "request-1", Mode: "udp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.handleStreamOpen(context.Background(), contractv1.Frame{StreamID: 1, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-controls:
		var message contractv1.StreamError
		if err := json.Unmarshal(frame.Payload, &message); err != nil || message.Code != "protocol_error" {
			t.Fatalf("protocol mismatch response: %+v, %v", message, err)
		}
	case <-time.After(time.Second):
		t.Fatal("protocol mismatch did not fail closed")
	}
	if len(sess.streams) != 0 {
		t.Fatal("protocol mismatch opened a local flow")
	}
}

func TestOversizeUDPDatagramClosesOnlyItsFlow(t *testing.T) {
	controls := make(chan contractv1.Frame, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &agentSession{
		limits: DefaultLimits(), logger: quietAgentLogger(), streams: make(map[uint32]*agentStream), maxStreamID: 2,
		closed: make(chan struct{}), controlWrites: make(chan agentWriteRequest, 32), dataWrites: make(chan agentWriteRequest, 2),
		writeMessage: func(_ context.Context, data []byte) error {
			frame, err := contractv1.DecodeFrame(data)
			if err == nil {
				controls <- frame
			}
			return err
		},
	}
	go sess.writeLoop()
	defer sess.shutdown()
	for _, id := range []uint32{1, 2} {
		streamCtx, streamCancel := context.WithCancel(ctx)
		defer streamCancel()
		sess.streams[id] = &agentStream{
			id: id, mode: "udp", ctx: streamCtx, cancel: streamCancel, logger: quietAgentLogger(),
			incoming: make(chan agentQueuedPayload, 1), space: make(chan struct{}, 1),
			streamBudget: newAgentByteBudget(4096), sessionBudget: newAgentByteBudget(4096),
		}
	}
	if err := sess.handleData(ctx, contractv1.Frame{StreamID: 1, Payload: make([]byte, maxUDPDatagram+1)}); err != nil {
		t.Fatal(err)
	}
	if _, exists := sess.streams[1]; exists {
		t.Fatal("oversize datagram left its flow active")
	}
	if _, exists := sess.streams[2]; !exists {
		t.Fatal("oversize datagram canceled a sibling flow")
	}
	select {
	case frame := <-controls:
		var message contractv1.StreamError
		if err := json.Unmarshal(frame.Payload, &message); err != nil || message.Code != "resource_limit" {
			t.Fatalf("oversize response: %+v, %v", message, err)
		}
	case <-time.After(time.Second):
		t.Fatal("oversize datagram did not send a terminal error")
	}
}
