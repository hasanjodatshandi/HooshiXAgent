package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOperationalReadinessAndMetrics(t *testing.T) {
	t.Parallel()

	gateway, err := New(NewSnapshotMetadata(), NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := gateway.Handler()

	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusOK || strings.TrimSpace(ready.Body.String()) != `{"status":"ready"}` {
		t.Fatalf("readyz status=%d body=%q", ready.Code, ready.Body.String())
	}

	metrics := httptest.NewRecorder()
	handler.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metrics.Code != http.StatusOK {
		t.Fatalf("metrics status=%d", metrics.Code)
	}
	body, err := io.ReadAll(metrics.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, metric := range []string{
		"hooshix_gateway_agent_sessions 0",
		"hooshix_gateway_active_streams 0",
		"hooshix_gateway_pending_handshakes 0",
		"hooshix_gateway_status_queue_depth 0",
		"hooshix_gateway_status_queue_limit 256",
		"hooshix_gateway_status_dropped_total 0",
		"hooshix_gateway_status_export_failures_total 0",
	} {
		if !strings.Contains(text, metric) {
			t.Fatalf("metrics missing %q: %s", metric, text)
		}
	}
	if strings.Contains(text, "{") || strings.Contains(text, "device") || strings.Contains(text, "endpoint") {
		t.Fatalf("operational metrics must remain unlabeled/aggregate: %s", text)
	}
}

func TestOperationalPathsDoNotFallThroughIngress(t *testing.T) {
	t.Parallel()

	gateway, err := New(NewSnapshotMetadata(), NopStatusSink{}, DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := gateway.Handler()
	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code == http.StatusNotFound {
			// Method mismatch is allowed to return 404/405 depending on ServeMux routing,
			// but it must never be resolved as a public tunnel route.
			continue
		}
		if recorder.Code == http.StatusOK {
			t.Fatalf("unexpected successful non-GET operational request for %s", path)
		}
	}
}
