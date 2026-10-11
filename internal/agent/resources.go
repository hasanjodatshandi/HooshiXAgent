package agent

import "github.com/hasanjodatshandi/HooshiXAgent/internal/agent/agentbudget"

// agentByteBudget aliases the pure-domain bounded byte budget so existing
// Agent session/stream code keeps its names while the policy lives in the
// ADR-0013 domain layer.
type agentByteBudget = agentbudget.ByteBudget

func newAgentByteBudget(limit int64) *agentByteBudget {
	return agentbudget.New(limit)
}

type agentQueuedPayload = agentbudget.QueuedPayload

// streamInputBudget returns the per-stream input byte budget for one stream
// mode. A Gateway admits an HTTP request body only up to its MaxRequestBytes,
// which is configured to stay inside this Agent's session input bound, so one
// admitted request is a finite amount of input the Agent must be able to hold
// while its local target drains it; giving it less turns an admitted upload
// into a resource_limit abort. A byte stream has no admission ceiling at all,
// so it keeps the tighter per-stream window and overflowing that window stays
// the genuine capacity breach the error describes.
func streamInputBudget(mode string, limits Limits) int64 {
	if mode == "tcp" || mode == "udp" {
		return limits.MaxStreamQueueBytes
	}
	if limits.MaxSessionQueueBytes > limits.MaxStreamQueueBytes {
		return limits.MaxSessionQueueBytes
	}
	return limits.MaxStreamQueueBytes
}

// minTunnelFrame is the smallest payload a peer realistically puts into one
// tunnel data frame. The Gateway serializes an admitted request with
// http.Request.Write, which wraps the stream writer in a bufio.Writer, so its
// frames arrive at bufio's 4096-byte flush size even though
// requestStreamWriter caps a chunk at 32 KiB; the socket paths read into 32 KiB
// buffers and therefore emit frames no larger, but no less frequent, than that.
// Queue slots are sized against the small end so the documented byte budget,
// not an accidental slot count, is what bounds a stream.
const minTunnelFrame = 4096

// streamQueueFrames returns the slot count for one stream's input queue. The
// byte budget is meant to be the limit that binds; a queue with fewer slots
// than the budget holds in minimum-size frames would fill its slots first,
// turning a documented multi-megabyte stream buffer into a far smaller one and
// aborting streams that still had room to buffer. MaxQueueFrames stays as the
// floor so an operator who lowers the byte budget keeps a usable queue.
func streamQueueFrames(maxFrames int, budgetBytes int64) int {
	frames := int(budgetBytes / minTunnelFrame)
	if frames < maxFrames {
		return maxFrames
	}
	return frames
}
