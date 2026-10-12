package agent

import (
	"errors"
	"io"
	"net"
	"time"

	contractv1 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv1"
)

// maxUDPDatagram keeps each datagram in one tunnel data frame and below the
// IPv6 minimum-MTU payload budget used by QUIC. Larger packets fail closed;
// splitting a UDP datagram would silently change its meaning.
const maxUDPDatagram = contractv1.MaxUDPDatagram

func (sess *agentSession) serveUDPStream(stream *agentStream, started time.Time) {
	conn, err := DialLocalUDPTarget(stream.ctx, stream.endpoint.Target, sess.limits.DialTimeout)
	if err != nil {
		sess.logger.Warn("stream dial failed", "stream_id", stream.id, "error", err)
		_ = sess.sendStreamTerminalError(stream, "local_target_unavailable", "approved local UDP target is unavailable", true)
		sess.finishStream(stream.id)
		return
	}
	defer conn.Close()
	go func() {
		<-stream.ctx.Done()
		_ = conn.Close()
	}()

	writerDone := make(chan error, 1)
	go func() {
		writeErr := sess.writeLocalUDP(stream, conn)
		if writeErr != nil {
			stream.cancel()
			_ = conn.Close()
		}
		writerDone <- writeErr
	}()

	buffer := make([]byte, maxUDPDatagram+1)
	var readErr error
	for {
		if err := conn.SetReadDeadline(time.Now().Add(sess.limits.IdleTimeout)); err != nil {
			readErr = err
			break
		}
		n, err := conn.Read(buffer)
		if n > maxUDPDatagram {
			readErr = errors.New("local UDP datagram exceeds tunnel limit")
			break
		}
		if err == nil {
			if sendErr := sess.sendFrame(stream.ctx, contractv1.KindData, stream.id, buffer[:n]); sendErr != nil {
				readErr = sendErr
				break
			}
		}
		if err != nil {
			readErr = err
			break
		}
	}
	peerClosed := stream.ctx.Err() != nil
	stream.cancel()
	_ = conn.Close()
	writeErr := <-writerDone
	if peerClosed {
		sess.finishUDPStream(stream, started, "peer_closed")
		return
	}
	if writeErr != nil {
		readErr = writeErr
	}
	outcome := "completed"
	var networkErr net.Error
	if errors.As(readErr, &networkErr) && networkErr.Timeout() {
		readErr = nil // an idle UDP flow expires normally
	}
	if readErr == nil {
		_ = sess.sendStreamTerminalClose(stream, "completed")
	} else {
		outcome = "local_error"
		_ = sess.sendStreamTerminalError(stream, "local_target_unavailable", "approved local UDP flow failed", true)
	}
	sess.finishUDPStream(stream, started, outcome)
}

// finishUDPStream closes the audit pair that serveStream opened: without a
// finished line the Agent log cannot say whether a flow was never routed or ran
// to completion.
func (sess *agentSession) finishUDPStream(stream *agentStream, started time.Time, outcome string) {
	sess.logger.Info("stream finished",
		"stream_id", stream.id,
		"endpoint_id", stream.endpoint.ID,
		"outcome", outcome,
		"duration", time.Since(started).Round(time.Millisecond),
	)
	sess.finishStream(stream.id)
}

func (sess *agentSession) writeLocalUDP(stream *agentStream, conn net.Conn) error {
	for {
		select {
		case <-stream.ctx.Done():
			return nil
		case queued := <-stream.incoming:
			stream.releaseQueued(queued.Size)
			if err := conn.SetWriteDeadline(time.Now().Add(sess.limits.WriteTimeout)); err != nil {
				return err
			}
			n, err := conn.Write(queued.Data)
			if err != nil {
				return err
			}
			if n != len(queued.Data) {
				return io.ErrShortWrite
			}
		}
	}
}
