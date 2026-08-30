package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func FuzzValidateLocalTarget(f *testing.F) {
	for _, seed := range []string{
		"127.0.0.1:80",
		"127.255.255.254:65535",
		"localhost:3000",
		"[::1]:443",
		"http://127.0.0.1:80",
		"169.254.169.254:80",
		"example.com:443",
		"127.0.0.1:0",
		"127.0.0.1:65536",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, target string) {
		first := ValidateLocalTarget(target)
		second := ValidateLocalTarget(target)
		if (first == nil) != (second == nil) {
			t.Fatalf("local-target validation is not deterministic for %q: first=%v second=%v", target, first, second)
		}
		if first != nil {
			return
		}

		host, portText, err := net.SplitHostPort(target)
		if err != nil {
			t.Fatalf("accepted target no longer splits as host:port: %q: %v", target, err)
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			t.Fatalf("accepted target has invalid port: %q", target)
		}
		if strings.ContainsAny(host, "/\\") || strings.Contains(target, "://") {
			t.Fatalf("accepted target contains a scheme/path: %q", target)
		}
		if strings.EqualFold(host, "localhost") {
			return
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			t.Fatalf("accepted target escaped loopback policy: %q", target)
		}
	})
}

func TestRunnerReconnectStormRemainsBounded(t *testing.T) {
	const (
		runners           = 12
		attemptsPerRunner = 20
	)

	limits := DefaultLimits()
	limits.ReconnectMin = time.Millisecond
	limits.ReconnectMax = time.Millisecond
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var wg sync.WaitGroup
	errCh := make(chan error, runners)
	counts := make([]atomic.Int32, runners)

	for i := 0; i < runners; i++ {
		runner, err := NewRunner(t.TempDir(), limits, logger)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		index := i
		runner.attempt = func(context.Context) error {
			if counts[index].Add(1) == attemptsPerRunner {
				cancel()
			}
			return errors.New("synthetic reconnect storm failure")
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- runner.Run(ctx)
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("bounded reconnect runner returned error: %v", err)
		}
	}
	for i := range counts {
		if got := counts[i].Load(); got != attemptsPerRunner {
			t.Fatalf("runner %d attempts=%d want=%d", i, got, attemptsPerRunner)
		}
	}
}
