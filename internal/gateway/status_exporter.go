package gateway

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

type statusExporter struct {
	sink        StatusSink
	logger      *slog.Logger
	queue       chan contractv1.GatewayStatusSignal
	emitTimeout time.Duration
	disabled    bool

	dropped  atomic.Uint64
	failures atomic.Uint64

	done      chan struct{}
	stopped   chan struct{}
	closeOnce sync.Once
	stateMu   sync.RWMutex
	closed    bool
}

func newStatusExporter(sink StatusSink, logger *slog.Logger, queueSize int, emitTimeout time.Duration) *statusExporter {
	exporter := &statusExporter{
		sink:        sink,
		logger:      logger,
		queue:       make(chan contractv1.GatewayStatusSignal, queueSize),
		emitTimeout: emitTimeout,
		done:        make(chan struct{}),
		stopped:     make(chan struct{}),
	}
	if _, ok := sink.(NopStatusSink); ok {
		exporter.disabled = true
		return exporter
	}
	go exporter.run()
	return exporter
}

func (exporter *statusExporter) enqueue(signal contractv1.GatewayStatusSignal) {
	if exporter == nil || exporter.disabled {
		return
	}
	exporter.stateMu.RLock()
	defer exporter.stateMu.RUnlock()
	if exporter.closed {
		exporter.dropped.Add(1)
		return
	}
	select {
	case exporter.queue <- signal:
	default:
		exporter.dropped.Add(1)
	}
}

func (exporter *statusExporter) run() {
	defer close(exporter.stopped)
	for {
		select {
		case signal := <-exporter.queue:
			exporter.emit(signal)
		case <-exporter.done:
			for {
				select {
				case signal := <-exporter.queue:
					exporter.emit(signal)
				default:
					return
				}
			}
		}
	}
}

func (exporter *statusExporter) emit(signal contractv1.GatewayStatusSignal) {
	ctx, cancel := context.WithTimeout(context.Background(), exporter.emitTimeout)
	err := exporter.sink.Emit(ctx, signal)
	cancel()
	if err != nil {
		exporter.failures.Add(1)
		exporter.logger.Warn("status sink failed", "error", err, "kind", signal.Kind)
	}
}

func (exporter *statusExporter) close(ctx context.Context) error {
	if exporter == nil || exporter.disabled {
		return nil
	}
	exporter.closeOnce.Do(func() {
		exporter.stateMu.Lock()
		exporter.closed = true
		close(exporter.done)
		exporter.stateMu.Unlock()
	})
	select {
	case <-exporter.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (exporter *statusExporter) snapshot() (queued, limit int, dropped, failures uint64) {
	if exporter == nil {
		return 0, 0, 0, 0
	}
	return len(exporter.queue), cap(exporter.queue), exporter.dropped.Load(), exporter.failures.Load()
}
