package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestGatewayHoldsMultipleTunnelsPerDevice proves the Phase-3 HA registry: a
// device may hold bounded concurrent tunnels (primary plus standby), the
// routing primary stays stable while a standby arrives, and the
// active_tunnels metric exposes both tunnels.
func TestGatewayHoldsMultipleTunnelsPerDevice(t *testing.T) {
	identity := newTestIdentity(t)
	metadata := testMetadata(t, identity, testRouteHost)
	limits := DefaultLimits()
	limits.MaxTunnelsPerDevice = 2
	gateway, err := New(metadata, NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer local.Close()

	primary := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer primary.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })
	primarySession := gateway.sessionForDevice(identity.deviceID)
	if primarySession == nil {
		t.Fatal("primary tunnel did not register")
	}

	// A second concurrent tunnel from the same device takes the standby HA
	// slot without evicting the routing primary.
	standby := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer standby.close()
	waitFor(t, 2*time.Second, func() bool {
		gateway.mu.RLock()
		defer gateway.mu.RUnlock()
		return len(gateway.tunnels[identity.deviceID]) == 2
	})

	// The routing primary must remain the original tunnel.
	if current := gateway.sessionForDevice(identity.deviceID); current != primarySession {
		t.Fatal("standby tunnel displaced the routing primary")
	}

	// The active_tunnels metric exposes both bounded tunnels.
	metrics := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "https://gateway.test/metrics", nil))
	body := metrics.Body.String()
	if !strings.Contains(body, "hooshix_gateway_active_tunnels 2\n") {
		t.Fatalf("active_tunnels must report 2:\n%s", body)
	}

	// Closing the primary transport promotes the standby tunnel so device
	// routing survives the primary loss without a fresh handshake.
	primary.close()
	waitFor(t, 4*time.Second, func() bool {
		current := gateway.sessionForDevice(identity.deviceID)
		return current != nil && current != primarySession
	})
	if promoted := gateway.sessionForDevice(identity.deviceID); promoted == nil {
		t.Fatal("standby tunnel was not promoted after primary loss")
	}
}

// TestGatewayDeviceTunnelBudgetFailsClosed proves the bounded per-device HA
// budget: when MaxTunnelsPerDevice is exhausted by the routing primary, a
// further concurrent tunnel is rejected and the routing primary survives.
func TestGatewayDeviceTunnelBudgetFailsClosed(t *testing.T) {
	identity := newTestIdentity(t)
	metadata := testMetadata(t, identity, testRouteHost)
	limits := DefaultLimits()
	limits.MaxTunnelsPerDevice = 1
	gateway, err := New(metadata, NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer local.Close()

	first := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer first.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })
	firstSession := gateway.sessionForDevice(identity.deviceID)
	if firstSession == nil {
		t.Fatal("primary tunnel did not register")
	}

	// An additional concurrent tunnel beyond the per-device budget must fail
	// closed: the gateway closes the overflow transport and the registry
	// keeps exactly the routing primary.
	overflow := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer overflow.close()
	waitFor(t, 2*time.Second, func() bool {
		gateway.mu.RLock()
		defer gateway.mu.RUnlock()
		return len(gateway.tunnels[identity.deviceID]) == 1
	})

	// The original tunnel must still own routing.
	if current := gateway.sessionForDevice(identity.deviceID); current != firstSession {
		t.Fatal("overflow attempt displaced the routing primary under a bounded device budget")
	}
}
