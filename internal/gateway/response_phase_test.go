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

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

// readUntilFrame reads frames until one matches, so tests are insensitive to
// the interleaving of stream_open/control frames with tunnel data.
func readUntilFrame(t *testing.T, ctx context.Context, peer *r5RawAgent, match func(contractv1.Frame) bool) contractv1.Frame {
	t.Helper()
	for {
		frame := peer.read(t, ctx)
		if match(frame) {
			return frame
		}
	}
}

func isStreamDataFor(streamID uint32) func(contractv1.Frame) bool {
	return func(frame contractv1.Frame) bool {
		return frame.Kind == contractv1.KindData && frame.StreamID == streamID
	}
}

// TestStalledTunnelResponsePhaseIsBoundedAndReleasesIngressSlot proves the
// response-phase deadline: an Agent that stays heartbeating but never answers a
// stream_open must not hold a global public-ingress slot indefinitely. The
// stalled request fails with 504, the stream receives a terminal stream_error
// so it detaches, and the bounded ingress slot is reusable.
func TestStalledTunnelResponsePhaseIsBoundedAndReleasesIngressSlot(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	limits.ResponsePhaseTimeout = 300 * time.Millisecond
	limits.MaxIngressInFlight = 1
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(gateway.Handler())
	defer tlsServer.Close()
	peer := authenticateRawAgentForR5(t, tlsServer.Client(), tlsServer.URL, identity)
	defer peer.conn.CloseNow()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	type result struct {
		status int
		body   string
	}
	results := make(chan result, 1)
	go func() {
		request, err := newPublicRequestAsync(t, tlsServer.URL+"/stalled", testRouteHost, nil)
		if err != nil {
			results <- result{status: -1, body: err.Error()}
			return
		}
		response, err := tlsServer.Client().Do(request)
		if err != nil {
			results <- result{status: -1, body: err.Error()}
			return
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		results <- result{status: response.StatusCode, body: string(body)}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	open := readUntilFrame(t, ctx, peer, func(frame contractv1.Frame) bool { return frame.Kind == contractv1.KindControl })
	var openMessage contractv1.StreamOpen
	if err := json.Unmarshal(open.Payload, &openMessage); err != nil {
		t.Fatalf("stream_open payload: %v", err)
	}
	if openMessage.MessageType != "stream_open" {
		t.Fatalf("first control frame=%q want stream_open", openMessage.MessageType)
	}
	// The stub Agent never answers the response: it only keeps the session up.

	select {
	case got := <-results:
		if got.status != http.StatusGatewayTimeout {
			t.Fatalf("stalled response status=%d body=%q want %d", got.status, got.body, http.StatusGatewayTimeout)
		}
		if !strings.Contains(got.body, "response phase deadline") {
			t.Fatalf("stalled response body=%q", got.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stalled tunnel response was not bounded by the response-phase deadline")
	}

	terminal := readUntilFrame(t, ctx, peer, func(frame contractv1.Frame) bool {
		return frame.Kind == contractv1.KindControl && frame.StreamID == open.StreamID
	})
	var streamError contractv1.StreamError
	if err := json.Unmarshal(terminal.Payload, &streamError); err != nil {
		t.Fatalf("terminal payload: %v", err)
	}
	if streamError.MessageType != "stream_error" || streamError.Code != "resource_limit" {
		t.Fatalf("terminal control=%+v want stream_error/resource_limit", streamError)
	}

	waitFor(t, time.Second, func() bool { return len(gateway.resources.ingressSlots) == 0 })
	sess := gateway.sessionForDevice(identity.deviceID)
	if sess == nil {
		t.Fatal("stalled response terminated the Agent session")
	}
	waitFor(t, time.Second, func() bool {
		sess.mu.Lock()
		defer sess.mu.Unlock()
		return len(sess.streams) == 0
	})

	// A fresh public request must still be admitted: the stalled request may
	// not have consumed the only bounded ingress slot.
	go func() {
		request, err := newPublicRequestAsync(t, tlsServer.URL+"/next", testRouteHost, nil)
		if err != nil {
			results <- result{status: -1, body: err.Error()}
			return
		}
		response, err := tlsServer.Client().Do(request)
		if err != nil {
			results <- result{status: -1, body: err.Error()}
			return
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		results <- result{status: response.StatusCode, body: string(body)}
	}()
	nextOpen := readUntilFrame(t, ctx, peer, func(frame contractv1.Frame) bool { return frame.Kind == contractv1.KindControl })
	var nextMessage contractv1.StreamOpen
	if err := json.Unmarshal(nextOpen.Payload, &nextMessage); err != nil {
		t.Fatalf("second stream_open payload: %v", err)
	}
	if nextMessage.MessageType != "stream_open" {
		t.Fatalf("second control frame=%q want stream_open", nextMessage.MessageType)
	}
	tunneled := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	if err := peer.sendData(ctx, nextOpen.StreamID, []byte(tunneled)); err != nil {
		t.Fatal(err)
	}
	peer.sendClose(t, ctx, nextOpen.StreamID, "completed")
	select {
	case got := <-results:
		if got.status != http.StatusOK || got.body != "ok" {
			t.Fatalf("second request status=%d body=%q want 200/ok", got.status, got.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second public request did not complete after the stalled stream detached")
	}
}

type ingressOutcome struct {
	status  int
	body    string
	elapsed time.Duration
	err     error
}

// startBodylessIngressPeer starts a bodyless public GET against the Gateway and
// returns the channel its outcome is reported on and the tunnel stream it was
// assigned.
func startBodylessIngressPeer(t *testing.T, tlsServer *httptest.Server, peer *r5RawAgent) (<-chan ingressOutcome, uint32, time.Time) {
	t.Helper()
	results := make(chan ingressOutcome, 1)
	started := time.Now()
	go func() {
		request, err := newPublicRequestAsync(t, tlsServer.URL+"/stream", testRouteHost, nil)
		if err != nil {
			results <- ingressOutcome{err: err}
			return
		}
		response, err := tlsServer.Client().Do(request)
		if err != nil {
			results <- ingressOutcome{err: err, elapsed: time.Since(started)}
			return
		}
		defer response.Body.Close()
		body, readErr := io.ReadAll(response.Body)
		results <- ingressOutcome{status: response.StatusCode, body: string(body), elapsed: time.Since(started), err: readErr}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	open := readUntilFrame(t, ctx, peer, func(frame contractv1.Frame) bool { return frame.Kind == contractv1.KindControl })
	// Reading the serialized public request proves the bodyless request itself
	// was forwarded over the tunnel before the response phase starts.
	readUntilFrame(t, ctx, peer, isStreamDataFor(open.StreamID))
	return results, open.StreamID, started
}

// TestBodylessPublicRequestKeepsProgressingTunnelResponse proves a bodyless
// public request is not truncated at ReadTimeout. Go's server starts its
// background read as soon as a bodyless request's handler begins, so an idle
// read deadline left armed by the request-body wrapper fires in the middle of
// the response phase, cancels the request context, and aborts a perfectly
// healthy tunneled response: before the change every bodyless request whose
// tunneled response outlived ReadTimeout failed with a 502
// "invalid tunneled response". The tunneled response here progresses chunk by
// chunk and is deliberately still in flight when ReadTimeout elapses, so a
// whole-response deadline (or a leaked idle deadline) truncates it.
func TestBodylessPublicRequestKeepsProgressingTunnelResponse(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	limits.ReadTimeout = time.Second
	if limits.ResponsePhaseTimeout <= limits.ReadTimeout {
		t.Fatalf("response phase timeout %s must stay above read timeout %s for this test", limits.ResponsePhaseTimeout, limits.ReadTimeout)
	}
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewUnstartedServer(gateway.Handler())
	tlsServer.Config.ReadHeaderTimeout = limits.ReadTimeout
	tlsServer.Config.ReadTimeout = 0
	tlsServer.Config.WriteTimeout = 0
	tlsServer.Config.IdleTimeout = limits.IdleTimeout
	tlsServer.StartTLS()
	defer tlsServer.Close()
	peer := authenticateRawAgentForR5(t, tlsServer.Client(), tlsServer.URL, identity)
	defer peer.conn.CloseNow()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	results, streamID, started := startBodylessIngressPeer(t, tlsServer, peer)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const (
		chunks    = 5
		chunkGap  = 300 * time.Millisecond
		chunkBody = "chunk"
	)
	if err := peer.sendData(ctx, streamID, []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n", len(chunkBody)*chunks)+chunkBody)); err != nil {
		t.Fatal(err)
	}
	for index := 1; index < chunks; index++ {
		time.Sleep(chunkGap)
		if err := peer.sendData(ctx, streamID, []byte(chunkBody)); err != nil {
			t.Fatal(err)
		}
	}
	peer.sendClose(t, ctx, streamID, "completed")

	select {
	case got := <-results:
		if got.err != nil {
			t.Fatalf("bodyless public request failed after %s (read timeout %s): status=%d body=%q error=%v",
				got.elapsed.Round(time.Millisecond), limits.ReadTimeout, got.status, got.body, got.err)
		}
		if got.status != http.StatusOK {
			t.Fatalf("bodyless public status=%d body=%q want %d", got.status, got.body, http.StatusOK)
		}
		if want := strings.Repeat(chunkBody, chunks); got.body != want {
			t.Fatalf("bodyless public response body=%q want %q (truncated at read timeout %s)", got.body, want, limits.ReadTimeout)
		}
		if got.elapsed <= limits.ReadTimeout {
			t.Fatalf("response finished in %s, inside read timeout %s: the test no longer exercises a response that outlives the read timeout",
				got.elapsed.Round(time.Millisecond), limits.ReadTimeout)
		}
		t.Logf("bodyless GET received %d bytes over %s (read timeout %s, response phase timeout %s)",
			len(got.body), time.Since(started).Round(time.Millisecond), limits.ReadTimeout, limits.ResponsePhaseTimeout)
	case <-time.After(15 * time.Second):
		t.Fatal("bodyless public request never completed")
	}
}

// TestBodylessStalledTunnelResponseReportsGatewayTimeout proves the
// client-visible status for a response-phase timeout on a bodyless request is
// the intended 504: the leaked idle read deadline cancelled the request context
// from Go's background read, which classified a Gateway-side timeout as a 502
// protocol error ("invalid tunneled response").
func TestBodylessStalledTunnelResponseReportsGatewayTimeout(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	limits.ReadTimeout = 500 * time.Millisecond
	limits.ResponsePhaseTimeout = 2 * time.Second
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewUnstartedServer(gateway.Handler())
	tlsServer.Config.ReadHeaderTimeout = limits.ReadTimeout
	tlsServer.Config.ReadTimeout = 0
	tlsServer.Config.WriteTimeout = 0
	tlsServer.Config.IdleTimeout = limits.IdleTimeout
	tlsServer.StartTLS()
	defer tlsServer.Close()
	peer := authenticateRawAgentForR5(t, tlsServer.Client(), tlsServer.URL, identity)
	defer peer.conn.CloseNow()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	results, streamID, _ := startBodylessIngressPeer(t, tlsServer, peer)
	// The stub Agent never answers this stream: the response phase expires.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	terminal := readUntilFrame(t, ctx, peer, func(frame contractv1.Frame) bool {
		return frame.Kind == contractv1.KindControl && frame.StreamID == streamID
	})
	var streamError contractv1.StreamError
	if err := json.Unmarshal(terminal.Payload, &streamError); err != nil {
		t.Fatalf("terminal payload: %v", err)
	}
	if streamError.MessageType != "stream_error" || streamError.Code != "resource_limit" {
		t.Fatalf("terminal control=%+v want stream_error/resource_limit", streamError)
	}

	select {
	case got := <-results:
		if got.status != http.StatusGatewayTimeout {
			t.Fatalf("bodyless stalled response status=%d body=%q want %d", got.status, got.body, http.StatusGatewayTimeout)
		}
		if !strings.Contains(got.body, "response phase deadline") {
			t.Fatalf("bodyless stalled response body=%q want the response phase deadline message", got.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bodyless stalled response was not bounded by the response phase deadline")
	}
}

// TestAgentControlledPublicStatusLineIsAllowlisted proves the public status
// line is a Gateway decision, not an Agent-controlled passthrough: 1xx
// (including 101 Switching Protocols) and non-HTTP codes abort with 502, while
// a legitimate 4xx is forwarded unchanged.
func TestAgentControlledPublicStatusLineIsAllowlisted(t *testing.T) {
	cases := []struct {
		name       string
		rawStatus  string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "switching-protocols",
			rawStatus:  "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: 0\r\n\r\n",
			wantStatus: http.StatusBadGateway,
			wantBody:   "status outside 200..599",
		},
		{
			name:       "early-hints",
			rawStatus:  "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\nContent-Length: 0\r\n\r\n",
			wantStatus: http.StatusBadGateway,
			wantBody:   "status outside 200..599",
		},
		{
			name:       "non-http-code",
			rawStatus:  "HTTP/1.1 999 Custom\r\nContent-Length: 2\r\n\r\nok",
			wantStatus: http.StatusBadGateway,
			wantBody:   "status outside 200..599",
		},
		{
			name:       "final-status-passed-through",
			rawStatus:  "HTTP/1.1 418 Teapot\r\nContent-Length: 3\r\n\r\ntea",
			wantStatus: http.StatusTeapot,
			wantBody:   "tea",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			identity := newTestIdentity(t)
			gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, DefaultLimits(), nil)
			if err != nil {
				t.Fatal(err)
			}
			tlsServer := httptest.NewTLSServer(gateway.Handler())
			defer tlsServer.Close()
			peer := authenticateRawAgentForR5(t, tlsServer.Client(), tlsServer.URL, identity)
			defer peer.conn.CloseNow()
			waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

			type result struct {
				status int
				body   string
			}
			results := make(chan result, 1)
			go func() {
				request, err := newPublicRequestAsync(t, tlsServer.URL+"/status", testRouteHost, nil)
				if err != nil {
					results <- result{status: -1, body: err.Error()}
					return
				}
				response, err := tlsServer.Client().Do(request)
				if err != nil {
					results <- result{status: -1, body: err.Error()}
					return
				}
				defer response.Body.Close()
				body, _ := io.ReadAll(response.Body)
				results <- result{status: response.StatusCode, body: string(body)}
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			open := readUntilFrame(t, ctx, peer, func(frame contractv1.Frame) bool { return frame.Kind == contractv1.KindControl })
			// Wait for the serialized public request so the stub Agent answers
			// only after the Gateway is waiting for the tunneled response.
			readUntilFrame(t, ctx, peer, isStreamDataFor(open.StreamID))
			if err := peer.sendData(ctx, open.StreamID, []byte(test.rawStatus)); err != nil {
				t.Fatal(err)
			}
			peer.sendClose(t, ctx, open.StreamID, "completed")

			select {
			case got := <-results:
				if got.status != test.wantStatus || !strings.Contains(got.body, test.wantBody) {
					t.Fatalf("status=%d body=%q want %d containing %q", got.status, got.body, test.wantStatus, test.wantBody)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("public request did not complete")
			}
		})
	}
}

// TestPublicIngressUsesIdleDeadlinesNotWholeMessageDeadlines proves the public
// listener is bounded per body chunk rather than per request/response, so a
// transfer that legitimately takes longer than the configured read/write
// timeout is not truncated (while a stalled peer stays bounded by the idle
// deadlines and the response-phase deadline).
func TestPublicIngressUsesIdleDeadlinesNotWholeMessageDeadlines(t *testing.T) {
	identity := newTestIdentity(t)
	limits := DefaultLimits()
	limits.ReadTimeout = time.Second
	limits.WriteTimeout = time.Second
	gateway, err := New(testMetadata(t, identity, testRouteHost), NopStatusSink{}, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := NewHTTPServer("127.0.0.1:0", gateway.Handler(), limits)
	if server.ReadTimeout != 0 || server.WriteTimeout != 0 {
		t.Fatalf("public listener still applies whole-message deadlines: read=%s write=%s", server.ReadTimeout, server.WriteTimeout)
	}
	if server.ReadHeaderTimeout != limits.ReadTimeout {
		t.Fatalf("read header timeout=%s want=%s", server.ReadHeaderTimeout, limits.ReadTimeout)
	}

	tlsServer := httptest.NewUnstartedServer(gateway.Handler())
	tlsServer.Config.ReadHeaderTimeout = server.ReadHeaderTimeout
	tlsServer.Config.ReadTimeout = server.ReadTimeout
	tlsServer.Config.WriteTimeout = server.WriteTimeout
	tlsServer.Config.IdleTimeout = server.IdleTimeout
	tlsServer.StartTLS()
	defer tlsServer.Close()

	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A response that streams for longer than the configured write
		// timeout, with progress inside every idle window.
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 5; i++ {
			_, _ = io.WriteString(w, "chunk")
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			time.Sleep(300 * time.Millisecond)
		}
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer local.Close()
	agent := connectMockAgent(t, context.Background(), tlsServer.URL, tlsServer.Client(), identity, local.URL)
	defer agent.close()
	waitFor(t, 2*time.Second, func() bool { return gateway.sessionForDevice(identity.deviceID) != nil })

	// A request body that also takes longer than the configured read timeout
	// in total, while every individual read makes progress.
	request, err := http.NewRequest(http.MethodPost, tlsServer.URL+"/slow", newSlowReader([][]byte{[]byte("slow-"), []byte("request-"), []byte("body")}, 400*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = testRouteHost
	request.ContentLength = -1
	response, err := tlsServer.Client().Do(request)
	if err != nil {
		t.Fatalf("slow public request failed: %v", err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("slow public response truncated: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("slow public status=%d body=%q", response.StatusCode, content)
	}
	if string(content) != "chunkchunkchunkchunkchunk" {
		t.Fatalf("slow public response body=%q", content)
	}
}

// slowReader yields each chunk after a delay, so a request can exceed a
// whole-request deadline while every individual read progresses.
type slowReader struct {
	chunks [][]byte
	delay  time.Duration
	index  int
}

func newSlowReader(chunks [][]byte, delay time.Duration) *slowReader {
	return &slowReader{chunks: chunks, delay: delay}
}

func (reader *slowReader) Read(data []byte) (int, error) {
	if reader.index >= len(reader.chunks) {
		return 0, io.EOF
	}
	time.Sleep(reader.delay)
	n := copy(data, reader.chunks[reader.index])
	reader.index++
	return n, nil
}
