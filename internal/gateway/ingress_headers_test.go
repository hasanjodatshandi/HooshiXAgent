package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// tenantHeaderEchoService returns a local tenant service that echoes the
// request Host and the forwarding headers it received, so a test can assert
// exactly what a tenant application observes.
func tenantHeaderEchoService(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Host", r.Host)
		w.Header().Set("X-Echo-Forwarded-For", r.Header.Get("X-Forwarded-For"))
		w.Header().Set("X-Echo-Real-Ip", r.Header.Get("X-Real-IP"))
		w.Header().Set("X-Echo-Forwarded-Proto", r.Header.Get("X-Forwarded-Proto"))
		w.Header().Set("X-Echo-Forwarded-Host", r.Header.Get("X-Forwarded-Host"))
		w.Header().Set("X-Echo-Forwarded", r.Header.Get("Forwarded"))
		w.Header().Set("X-Echo-Path", r.URL.Path)
		_, _ = fmt.Fprintf(w, "tenant:%s", r.URL.Path)
	}))
}

// TestTenantOperationalPathsAreNotShadowedByGatewayEndpoints proves a tenant
// host keeps its own operational-looking paths: /healthz (and the other
// Gateway-local paths) must be routed to the tenant application, never to a
// Gateway-local handler.
func TestTenantOperationalPathsAreNotShadowedByGatewayEndpoints(t *testing.T) {
	identity := newTestIdentity(t)
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	local := tenantHeaderEchoService(t)
	defer local.Close()
	agent := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agent.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		response, err := tlsServer.Client().Do(newPublicRequest(t, tlsServer.URL+path, testRouteHost, nil))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("%s status=%d body=%q", path, response.StatusCode, body)
		}
		if string(body) != "tenant:"+path {
			t.Fatalf("%s reached the Gateway instead of the tenant application: body=%q", path, body)
		}
	}

	// The Gateway's own operational endpoints remain reachable on their own
	// administrative handler.
	recorder := httptest.NewRecorder()
	gateway.OpsHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("ops healthz status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

// TestClientSuppliedForwardingHeadersAreNeverTrusted proves the client address
// a tenant application sees cannot be spoofed by an internet client: inbound
// forwarding headers are stripped, the Host is rewritten to the canonical
// metadata hostname, and the values are re-derived from the trusted peer.
func TestClientSuppliedForwardingHeadersAreNeverTrusted(t *testing.T) {
	t.Run("untrusted peer", func(t *testing.T) {
		identity := newTestIdentity(t)
		gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, DefaultLimits(), nil)
		if err != nil {
			t.Fatal(err)
		}
		tlsServer := httptest.NewTLSServer(gateway.Handler())
		defer tlsServer.Close()
		local := tenantHeaderEchoService(t)
		defer local.Close()
		agent := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
		defer agent.close()
		waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

		request := newPublicRequest(t, tlsServer.URL+"/headers", testRouteHost, nil)
		request.Host = "Demo.Hooshix.Test:8443"
		request.Header.Set("X-Forwarded-For", "203.0.113.9")
		request.Header.Set("X-Real-IP", "203.0.113.9")
		request.Header.Set("Forwarded", "for=203.0.113.9;proto=http")
		request.Header.Set("X-Forwarded-Proto", "http")
		request.Header.Set("X-Forwarded-Host", "attacker.example")
		request.Header.Set("X-Forwarded-Port", "9999")
		response, err := tlsServer.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status=%d", response.StatusCode)
		}
		if got := response.Header.Get("X-Echo-Forwarded-For"); got != "127.0.0.1" {
			t.Fatalf("tenant saw X-Forwarded-For=%q want the immediate peer 127.0.0.1", got)
		}
		if got := response.Header.Get("X-Echo-Real-Ip"); got != "127.0.0.1" {
			t.Fatalf("tenant saw X-Real-IP=%q", got)
		}
		if got := response.Header.Get("X-Echo-Forwarded-Proto"); got != "https" {
			t.Fatalf("tenant saw X-Forwarded-Proto=%q want https", got)
		}
		// The tunneled Host is the canonical metadata hostname (the mock Agent
		// rewrites Host for its local target, so the Gateway-side value is
		// asserted directly in TestForwardingHeaderSanitisationIsComplete).
		if got := response.Header.Get("X-Echo-Forwarded-Host"); got != testRouteHost {
			t.Fatalf("tenant saw X-Forwarded-Host=%q want %q", got, testRouteHost)
		}
		if forwarded := response.Header.Get("X-Echo-Forwarded"); strings.Contains(forwarded, "203.0.113.9") {
			t.Fatalf("client-supplied Forwarded value reached the tenant: %q", forwarded)
		}
	})

	t.Run("trusted edge supplies the client hop", func(t *testing.T) {
		identity := newTestIdentity(t)
		limits := DefaultLimits()
		limits.TrustedProxyPeers = []string{"127.0.0.1/32"}
		gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
		if err != nil {
			t.Fatal(err)
		}
		tlsServer := httptest.NewTLSServer(gateway.Handler())
		defer tlsServer.Close()
		local := tenantHeaderEchoService(t)
		defer local.Close()
		agent := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
		defer agent.close()
		waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

		// The edge appends the address it observed: the last hop is the one
		// the trusted edge vouches for.
		request := newPublicRequest(t, tlsServer.URL+"/headers", testRouteHost, nil)
		request.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.7")
		request.Header.Set("X-Real-IP", "203.0.113.9")
		response, err := tlsServer.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status=%d", response.StatusCode)
		}
		if got := response.Header.Get("X-Echo-Forwarded-For"); got != "198.51.100.7" {
			t.Fatalf("tenant saw X-Forwarded-For=%q want the trusted edge's observed client hop", got)
		}
		if got := response.Header.Get("X-Echo-Real-Ip"); got != "198.51.100.7" {
			t.Fatalf("tenant saw X-Real-IP=%q", got)
		}
	})

	t.Run("malformed trusted proxy configuration fails startup", func(t *testing.T) {
		identity := newTestIdentity(t)
		limits := DefaultLimits()
		limits.TrustedProxyPeers = []string{"not-a-cidr"}
		if _, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil); err == nil {
			t.Fatal("invalid trusted proxy entry was accepted")
		}
	})
}

// TestForwardingHeaderSanitisationIsComplete is a focused unit check that every
// client-supplied forwarding header is removed before the tunnel request is
// built, independent of the peer trust configuration.
func TestForwardingHeaderSanitisationIsComplete(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://demo.hooshix.test/thing", nil)
	request.Host = "DEMO.Hooshix.Test:8443"
	request.RemoteAddr = "203.0.113.44:5555"
	for _, name := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Real-IP", "Forwarded"} {
		request.Header.Set(name, "spoofed")
	}
	_, route := metadataRecords(identity, testRouteHost)
	cloned := gateway.cloneRequestForTunnel(request, route)
	for _, name := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Real-IP", "Forwarded"} {
		if strings.Contains(cloned.Header.Get(name), "spoofed") {
			t.Fatalf("client-supplied %s survived sanitisation: %q", name, cloned.Header.Get(name))
		}
	}
	if cloned.Header.Get("X-Forwarded-For") != "203.0.113.44" {
		t.Fatalf("X-Forwarded-For=%q want the immediate peer", cloned.Header.Get("X-Forwarded-For"))
	}
	if cloned.Host != testRouteHost {
		t.Fatalf("Host=%q want %q", cloned.Host, testRouteHost)
	}
	encoded, err := json.Marshal(cloned.Header)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "spoofed") {
		t.Fatalf("spoofed value survived in the tunneled headers: %s", encoded)
	}
}
