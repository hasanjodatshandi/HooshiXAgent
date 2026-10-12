package svc

import (
	"io"
	"log/slog"
)

// newForegroundLogger builds the diagnostic sink for a supervisor that runs in
// the foreground instead of under the SCM: the console debug path on Windows
// and the systemd --user / LaunchAgent path on Linux and macOS. Those hosts
// capture the process's stderr, so the caller must hand over the real stream.
// A discarding writer here erases every diagnostic for the whole service run,
// which is why no call site is allowed to pass a nil or throwaway writer.
func newForegroundLogger(out io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo}))
}
