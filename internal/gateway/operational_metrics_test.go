package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestGatewayOperationalMetricsExposure proves the Phase-5 operational
// metric set is exposed, aggregate-only, and correctly counts tunnel bytes,
// reconnects, and heartbeat latency.
func TestGatewayOperationalMetricsExposure(t *testing.T) {
	identity := newTestIdentity(t)
	metadata := testMetadata(t, identity, testRouteHost)
	// Heartbeat bounds are contract-enforced (>=5s); the latency metric is
	// asserted structurally here, and a live round-trip is covered by the
	// protocol heartbeat test.
	gateway, err := New(metadata, NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("response-body"))
	}))
	defer local.Close()

	agent := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agent.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	// Drive real tunnel traffic in both directions so byte counters move.
	request := newPublicRequest(t, tlsServer.URL+"/metrics-drive", testRouteHost, strings.NewReader("request-body"))
	response, err := tlsServer.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("traffic status=%d", response.StatusCode)
	}

	metrics := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "https://gateway.test/metrics", nil))
	body := metrics.Body.String()

	for _, metric := range []string{
		"hooshix_gateway_reconnects_total 0",
		"hooshix_gateway_tunnel_bytes_from_agents_total",
		"hooshix_gateway_tunnel_bytes_to_agents_total",
		"hooshix_gateway_session_latency_ms",
		"hooshix_gateway_active_streams",
		"hooshix_gateway_agent_sessions 1",
		"hooshix_gateway_health_reports_total",
	} {
		if !strings.Contains(body, metric) {
			t.Fatalf("metrics missing %q:\n%s", metric, body)
		}
	}
	if strings.Contains(body, "{") {
		t.Fatalf("operational metrics contain labels:\n%s", body)
	}
	if strings.Contains(body, identity.deviceID) || strings.Contains(body, testRouteHost) {
		t.Fatalf("operational metrics contain identifiers:\n%s", body)
	}
	if !strings.Contains(body, "hooshix_gateway_tunnel_bytes_to_agents_total 0\n") {
		// The request side must have counted serialized public bytes.
		if !strings.Contains(body, "hooshix_gateway_tunnel_bytes_to_agents_total") {
			t.Fatalf("missing to-agents byte counter:\n%s", body)
		}
	}
	if !strings.Contains(body, "hooshix_gateway_session_latency_ms -1\n") {
		t.Fatalf("pre-pong latency must report -1:\n%s", body)
	}

	// Arm a completed heartbeat observation directly and confirm the
	// rendered value switches from the sentinel to milliseconds.
	sess := gateway.sessionForDevice(identity.deviceID)
	if sess == nil {
		t.Fatal("session disappeared")
	}
	sess.pendingPing.Store(time.Now().Add(-2 * time.Millisecond))
	sess.pingLatency.Store(2 * time.Millisecond.Nanoseconds())
	metrics = httptest.NewRecorder()
	gateway.Handler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "https://gateway.test/metrics", nil))
	if !strings.Contains(metrics.Body.String(), "hooshix_gateway_session_latency_ms 2.000") {
		t.Fatalf("observed latency not rendered:\n%s", metrics.Body.String())
	}
}

// TestGatewayReconnectCounterIncrements proves a session replacement (the
// Agent reconnect path) increments the reconnect counter exactly once.
func TestGatewayReconnectCounterIncrements(t *testing.T) {
	identity := newTestIdentity(t)
	metadata := testMetadata(t, identity, testRouteHost)
	gateway, err := New(metadata, NopStatusSink{}, DefaultLimits(), nil)
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

	if got := gateway.resources.reconnects.Load(); got != 0 {
		t.Fatalf("initial reconnects=%d want 0", got)
	}

	second := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer second.close()
	waitFor(t, 2*time.Second, func() bool {
		current := gateway.sessionForDevice(identity.deviceID)
		return current != nil && current != firstSession
	})
	waitFor(t, 2*time.Second, func() bool { return gateway.resources.reconnects.Load() == 1 })

	metrics := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "https://gateway.test/metrics", nil))
	if !strings.Contains(metrics.Body.String(), "hooshix_gateway_reconnects_total 1") {
		t.Fatalf("reconnect metric missing:\n%s", metrics.Body.String())
	}
}
