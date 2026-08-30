package gateway

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func FuzzCanonicalHostname(f *testing.F) {
	for _, seed := range []string{
		"demo.hooshix.test",
		" DEMO.HOOSHIX.TEST. ",
		"demo.hooshix.test:443",
		"example.com:",
		"",
		"[::1]:443",
		"host:443:extra",
		"0 .",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		canonical := canonicalHostname(raw)
		if canonical != strings.ToLower(canonical) {
			t.Fatalf("canonical hostname contains upper-case data: %q", canonical)
		}

		source := NewSnapshotMetadata()
		err := source.addRouteJSON([]byte(`{"contract_version":1,"assignment_id":"assign-fuzz","endpoint_id":"endpoint-fuzz","public_hostname":"demo.hooshix.test","device_id":"device-fuzz","local_endpoint_id":"local-fuzz","enabled":true,"not_before":"2026-08-29T00:00:00Z","expires_at":"2026-09-01T00:00:00Z"}`))
		if err != nil {
			t.Fatal(err)
		}
		record, lookupErr := source.RouteByHostname(context.Background(), raw, time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC))
		if canonical == testRouteHost {
			if lookupErr != nil || record.PublicHostname != testRouteHost {
				t.Fatalf("canonical route lookup failed raw=%q canonical=%q record=%q err=%v", raw, canonical, record.PublicHostname, lookupErr)
			}
			return
		}
		if !errors.Is(lookupErr, ErrMetadataNotFound) {
			t.Fatalf("non-matching hostname returned unexpected error raw=%q canonical=%q err=%v", raw, canonical, lookupErr)
		}
	})
}

func FuzzSnapshotMetadataRecordParsing(f *testing.F) {
	f.Add([]byte(`{"contract_version":1,"assignment_id":"assign-001","endpoint_id":"endpoint-001","public_hostname":"demo.hooshix.example","device_id":"device-001","local_endpoint_id":"local-http-001","enabled":true,"not_before":"2026-08-29T06:00:00Z","expires_at":"2026-08-30T06:00:00Z"}`), uint8(1))
	f.Add([]byte(`{"contract_version":1,"event_id":"revoke-001","subject_kind":"device","subject_id":"device-001","effective_at":"2026-08-29T12:00:00Z","reason_code":"security_hold"}`), uint8(2))
	f.Add([]byte(`{"contract_version":1,"assignment_id":"a","assignment_id":"b"}`), uint8(1))
	f.Add([]byte{0xff}, uint8(0))

	f.Fuzz(func(t *testing.T, data []byte, kind uint8) {
		source := NewSnapshotMetadata()
		var err error
		switch kind % 3 {
		case 0:
			err = source.addAuthorizationJSON(data)
		case 1:
			err = source.addRouteJSON(data)
		case 2:
			err = source.addRevocationJSON(data)
		}
		readyErr := source.Ready()
		if err != nil && readyErr == nil {
			t.Fatalf("rejected metadata did not fail readiness: %v", err)
		}
		if err == nil && readyErr != nil {
			t.Fatalf("accepted metadata unexpectedly failed readiness: %v", readyErr)
		}
	})
}

func FuzzTunneledHTTPResponseParsing(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Test: yes\r\n\r\nok"), uint16(4096))
	f.Add([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"), uint16(4096))
	f.Add([]byte("HTTP/1.1 200 OK\r\nX-Large: "+strings.Repeat("x", 128)+"\r\n\r\n"), uint16(32))
	f.Add([]byte("not-http"), uint16(64))

	f.Fuzz(func(t *testing.T, data []byte, rawLimit uint16) {
		limit := int64(rawLimit%8192) + 1
		limited := newResponseHeaderLimitReader(bytes.NewReader(data), limit)
		response, err := http.ReadResponse(bufio.NewReader(limited), nil)
		if limited.remaining < 0 {
			t.Fatalf("header parser exceeded configured limit: remaining=%d limit=%d", limited.remaining, limit)
		}
		if errors.Is(err, errResponseHeaderTooLarge) {
			return
		}
		if err != nil || response == nil {
			return
		}
		defer response.Body.Close()

		before := response.Header.Clone()
		removeHopByHopHeaders(response.Header)
		once := response.Header.Clone()
		removeHopByHopHeaders(response.Header)
		if !headersEqual(once, response.Header) {
			t.Fatalf("hop-by-hop header removal is not idempotent: before=%v after=%v", before, response.Header)
		}

		if response.ContentLength < 0 || response.ContentLength <= 1024 {
			written, _, _ := copyTunneledResponseBody(io.Discard, response, 1024)
			if response.ContentLength < 0 && written > 1024 {
				t.Fatalf("unknown-length body copy exceeded limit: %d", written)
			}
		}
	})
}

func headersEqual(left, right http.Header) bool {
	if len(left) != len(right) {
		return false
	}
	for key, leftValues := range left {
		rightValues, ok := right[key]
		if !ok || len(leftValues) != len(rightValues) {
			return false
		}
		for i := range leftValues {
			if leftValues[i] != rightValues[i] {
				return false
			}
		}
	}
	return true
}

func TestRequestStreamWriterSlowConsumerBackpressureIsBounded(t *testing.T) {
	budget := newByteBudget(2 * requestStreamChunkSize)
	var rejected atomic.Uint64
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	var sends atomic.Int32

	writer := newRequestStreamWriter(t.Context(), budget, &rejected, func(_ context.Context, payload []byte) error {
		if len(payload) > requestStreamChunkSize {
			t.Fatalf("streamed chunk size=%d exceeds bound=%d", len(payload), requestStreamChunkSize)
		}
		if sends.Add(1) == 1 {
			close(firstEntered)
			<-releaseFirst
		}
		return nil
	})

	done := make(chan error, 1)
	go func() {
		_, err := writer.Write(bytes.Repeat([]byte{'x'}, 2*requestStreamChunkSize))
		done <- err
	}()

	select {
	case <-firstEntered:
	case <-time.After(time.Second):
		t.Fatal("slow-consumer send did not start")
	}
	select {
	case err := <-done:
		t.Fatalf("writer completed before slow consumer released: %v", err)
	default:
	}
	used, _, _ := budget.snapshot()
	if used != requestStreamChunkSize {
		t.Fatalf("slow consumer retained %d bytes want exactly one chunk=%d", used, requestStreamChunkSize)
	}

	close(releaseFirst)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("writer did not resume after slow consumer released")
	}
	if used, _, _ := budget.snapshot(); used != 0 {
		t.Fatalf("slow-consumer completion leaked ingress budget: %d", used)
	}
	if rejected.Load() != 0 {
		t.Fatalf("slow-consumer scenario unexpectedly rejected chunks: %d", rejected.Load())
	}
}
