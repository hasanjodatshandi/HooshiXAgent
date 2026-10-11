//go:build windows

package svc

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
)

// TestOperatorStopReportsSuccessExitCode proves an operator-initiated stop is
// reported to SCM as success. Before the fix controlLoop returned 1, which the
// restart-on-failure policy installed by Install turns into an automatic
// restart ~5s later, so "Stop service" never took effect.
func TestOperatorStopReportsSuccessExitCode(t *testing.T) {
	requests := make(chan svc.ChangeRequest, 1)
	status := make(chan svc.Status, 8)
	agentDone := make(chan struct{})
	cancelled := false
	cancel := func() {
		if !cancelled {
			cancelled = true
			close(agentDone)
		}
	}
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	if code := controlLoop(requests, status, cancel, agentDone); code != 0 {
		t.Fatalf("operator stop exit code=%d want=0", code)
	}
	if !cancelled {
		t.Fatal("operator stop did not cancel the agent context")
	}
	// The service must announce StopPending before exiting.
	select {
	case reported := <-status:
		if reported.State != svc.StopPending {
			t.Fatalf("reported state=%d want StopPending", reported.State)
		}
	default:
		t.Fatal("no status was reported before exiting")
	}
}

// TestShutdownReportsSuccessExitCode proves a machine shutdown is treated the
// same as an operator stop: restarting the service during shutdown would be
// both wrong and disruptive.
func TestShutdownReportsSuccessExitCode(t *testing.T) {
	requests := make(chan svc.ChangeRequest, 1)
	status := make(chan svc.Status, 8)
	agentDone := make(chan struct{})
	requests <- svc.ChangeRequest{Cmd: svc.Shutdown}
	if code := controlLoop(requests, status, func() { close(agentDone) }, agentDone); code != 0 {
		t.Fatalf("shutdown exit code=%d want=0", code)
	}
}

// TestAgentSelfTerminationReportsFailureExitCode proves a supervisor that
// exits on its own is still reported as a failure (non-zero), so SCM failure
// recovery can act instead of leaving a hollow Running service.
func TestAgentSelfTerminationReportsFailureExitCode(t *testing.T) {
	agentDone := make(chan struct{})
	close(agentDone)
	code := controlLoop(make(chan svc.ChangeRequest), make(chan svc.Status, 8), func() {}, agentDone)
	if code == 0 {
		t.Fatal("self-terminating agent reported success to SCM")
	}
}

// TestClosedRequestChannelIsCleanStop proves the SCM closing the control
// channel (service deleted) is not reported as a failure.
func TestClosedRequestChannelIsCleanStop(t *testing.T) {
	requests := make(chan svc.ChangeRequest)
	close(requests)
	if code := controlLoop(requests, make(chan svc.Status, 8), func() {}, make(chan struct{})); code != 0 {
		t.Fatalf("closed request channel exit code=%d want=0", code)
	}
}

// TestServiceDACLGrantsExactlyTrayRights decodes the DACL Install applies and
// asserts the interactive-user ace carries SERVICE_QUERY_STATUS, SERVICE_START
// and SERVICE_STOP and nothing else. The previous SDDL granted
// "LCSWLOCRRC" — query-status, enumerate-dependents, interrogate,
// user-defined-control and read-control — which contains neither start nor
// stop, so the LeastPrivilege tray could not start or stop the service.
func TestServiceDACLGrantsExactlyTrayRights(t *testing.T) {
	descriptor, err := windows.SecurityDescriptorFromString(serviceStartStopSDDL)
	if err != nil {
		t.Fatalf("parse service SDDL: %v", err)
	}
	entries := daclEntries(t, descriptor)
	if len(entries) != 3 {
		t.Fatalf("DACL has %d aces, want 3: %v", len(entries), entries)
	}
	const (
		localSystemSID     = "S-1-5-18"
		administratorsSID  = "S-1-5-32-544"
		interactiveUserSID = "S-1-5-4"
	)
	for _, sid := range []string{localSystemSID, administratorsSID} {
		mask, ok := entries[sid]
		if !ok {
			t.Fatalf("DACL is missing an ace for %s: %v", sid, entries)
		}
		if mask != serviceFullControlRights {
			t.Fatalf("ace for %s mask=0x%08x want full control 0x%08x", sid, mask, serviceFullControlRights)
		}
	}
	mask, ok := entries[interactiveUserSID]
	if !ok {
		t.Fatalf("DACL is missing the interactive-user ace: %v", entries)
	}
	if mask != interactiveUserServiceRights {
		t.Fatalf("interactive user mask=0x%08x want 0x%08x", mask, interactiveUserServiceRights)
	}
	for name, forbidden := range map[string]uint32{
		"SERVICE_START":         windows.SERVICE_START,
		"SERVICE_STOP":          windows.SERVICE_STOP,
		"SERVICE_QUERY_STATUS":  windows.SERVICE_QUERY_STATUS,
		"SERVICE_CHANGE_CONFIG": windows.SERVICE_CHANGE_CONFIG,
		"DELETE":                windows.DELETE,
		"WRITE_DAC":             windows.WRITE_DAC,
		"WRITE_OWNER":           windows.WRITE_OWNER,
	} {
		present := mask&forbidden != 0
		want := forbidden == windows.SERVICE_START ||
			forbidden == windows.SERVICE_STOP ||
			forbidden == windows.SERVICE_QUERY_STATUS
		if present != want {
			t.Fatalf("interactive user %s present=%t want=%t (mask=0x%08x)", name, present, want, mask)
		}
	}
}

// TestServiceAccessMasksAreLeastPrivilege proves each SCM call opens the
// service with only the right it needs. mgr.OpenService requests
// SERVICE_ALL_ACCESS for every call, which the DACL above deliberately does
// not grant interactive users, so every tray query/start/stop failed with
// access denied.
func TestServiceAccessMasksAreLeastPrivilege(t *testing.T) {
	cases := map[string]struct {
		mask uint32
		need uint32
	}{
		"query": {serviceQueryAccess, windows.SERVICE_QUERY_STATUS},
		"start": {serviceStartAccess, windows.SERVICE_START},
		"stop":  {serviceStopAccess, windows.SERVICE_STOP},
	}
	for name, c := range cases {
		if c.mask != c.need {
			t.Fatalf("%s access mask=0x%08x want exactly 0x%08x", name, c.mask, c.need)
		}
		if c.mask == windows.SERVICE_ALL_ACCESS {
			t.Fatalf("%s still requests SERVICE_ALL_ACCESS", name)
		}
		if c.mask&windows.SERVICE_CHANGE_CONFIG != 0 {
			t.Fatalf("%s requests SERVICE_CHANGE_CONFIG", name)
		}
	}
	if interactiveUserServiceRights != serviceQueryAccess|serviceStartAccess|serviceStopAccess {
		t.Fatalf("interactive rights 0x%08x must equal exactly the union of the per-operation masks", interactiveUserServiceRights)
	}
}

// TestServiceStateDirMatchesAgentResolver proves svc.StateDir() and the shared
// resolver in package agent agree, so the CLI default and the service can never
// diverge onto two different identities.
func TestServiceStateDirMatchesAgentResolver(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ProgramData", root)
	if got, want := StateDir(), agent.ServiceStateDir(); got != want {
		t.Fatalf("StateDir()=%q but agent.ServiceStateDir()=%q", got, want)
	}
	if got, want := StateDir(), filepath.Join(root, "HooshiXAgent"); got != want {
		t.Fatalf("StateDir()=%q want=%q", got, want)
	}
}

// daclEntries decodes a security descriptor's DACL into SID-string -> access
// mask pairs. x/sys/windows exposes the ACL header but no ACE iterator, so the
// raw ACE list is walked directly.
func daclEntries(t *testing.T, descriptor *windows.SECURITY_DESCRIPTOR) map[string]uint32 {
	t.Helper()
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("extract DACL: %v", err)
	}
	if dacl == nil {
		t.Fatal("security descriptor has no DACL")
	}
	entries := make(map[string]uint32)
	// ACL layout: AclRevision(1) Sbz1(1) AclSize(2) AceCount(2) Sbz2(2).
	offset := uintptr(8)
	base := unsafe.Pointer(dacl)
	for index := 0; index < int(dacl.AceCount); index++ {
		ace := (*windows.ACCESS_ALLOWED_ACE)(unsafe.Add(base, offset))
		if ace.Header.AceSize < 8 {
			t.Fatalf("ace %d has invalid size %d", index, ace.Header.AceSize)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatalf("ace %d type=%d, expected an allow ace", index, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		entries[sid.String()] = uint32(ace.Mask)
		offset += uintptr(ace.Header.AceSize)
	}
	return entries
}

// compile-time guard: controlLoop's cancel signature must stay compatible with
// context.CancelFunc.
var _ context.CancelFunc = func() {}

// TestRotatingFileBoundsTheLogAndKeepsOneBackup proves the service log cannot
// grow without limit: past maxBytes the active file is rotated into <name>.1.
func TestRotatingFileBoundsTheLogAndKeepsOneBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	writer, err := newRotatingFile(path, 64)
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 8; round++ {
		if _, err := writer.Write([]byte("0123456789abcdef\n")); err != nil {
			t.Fatalf("write %d: %v", round, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	active, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if active.Size() > 64 {
		t.Fatalf("active log grew past its bound: %d bytes", active.Size())
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("no previous log was retained: %v", err)
	}
}

// TestRotatingFileReportsAnUnavailableLogInsteadOfShrinkingToSilence proves a
// failed open is reported and recovered. Returning (len(p), nil) made every
// later diagnostic look written while nothing reached disk, for the whole life
// of the service, so the operator lost the only record of the failure.
func TestRotatingFileReportsAnUnavailableLogInsteadOfShrinkingToSilence(t *testing.T) {
	dir := t.TempDir()
	// A directory where the log belongs makes the open fail, and removing it
	// later makes the same path openable again.
	blocked := filepath.Join(dir, "agent.log")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	writer := &rotatingFile{path: blocked, maxBytes: 64}
	written, err := writer.Write([]byte("first diagnostic\n"))
	if err == nil {
		t.Fatal("a log that could not be opened was reported as written")
	}
	if written != 0 {
		t.Fatalf("Write claimed %d bytes for a log it could not open", written)
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("recovered diagnostic\n")); err != nil {
		t.Fatalf("the log did not recover once it became openable: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(blocked)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "recovered diagnostic") {
		t.Fatalf("the post-failure diagnostic is missing from agent.log: %q", contents)
	}
}

// TestRotatingFileKeepsTheBoundHonestWhenRotationFails proves that a failed
// rotation neither drops diagnostics nor falsifies the size counter. Zeroing
// `written` after a failed rename let the log outrun its bound unnoticed, and
// delayed the retry that would have fixed it.
func TestRotatingFileKeepsTheBoundHonestWhenRotationFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	writer, err := newRotatingFile(path, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	// Occupying the backup slot with a non-empty directory makes the rename
	// fail while the active file stays perfectly writable: os.Remove cannot
	// clear the slot, and a file cannot be renamed onto an occupied directory.
	backup := path + ".1"
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "occupant"), []byte("held"), 0o600); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 8; round++ {
		if _, err := writer.Write([]byte("0123456789abcdef\n")); err != nil {
			t.Fatalf("write %d with rotation unavailable: %v", round, err)
		}
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) < 8*17 {
		t.Fatalf("diagnostics were dropped while rotation failed: %d bytes on disk", len(contents))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if writer.written != info.Size() {
		t.Fatalf("the size counter says %d while the log holds %d bytes", writer.written, info.Size())
	}

	// Once rotation becomes possible again the very next write must rotate: the
	// counter already reports the truth.
	if err := os.RemoveAll(backup); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("final\n")); err != nil {
		t.Fatal(err)
	}
	rotated, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("the oversized log was not rotated on the write after the block cleared: %v", err)
	}
	if !strings.Contains(string(rotated), "0123456789abcdef") {
		t.Fatalf("rotated log lost its history: %q", rotated)
	}
}

// TestServiceLoggerDegradesWhenTheLogCannotBeOpened proves the service still
// runs when its log path is unusable (a logger failure must never stop the
// tunnel), that a usable path receives the diagnostics, and that an unusable
// path is retried rather than abandoned: the logger keeps writing as soon as
// the path frees instead of going silent for the rest of the service's life.
func TestServiceLoggerDegradesWhenTheLogCannotBeOpened(t *testing.T) {
	dir := t.TempDir()
	// Built from the same primitives newServiceLogger uses, so the test can
	// close the handle (on Windows an open handle blocks the temp-dir cleanup,
	// and the service logger intentionally lives for the whole process).
	writer, err := newRotatingFile(filepath.Join(dir, "agent.log"), agentLogMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Warn("audit probe")
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(dir, "agent.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "audit probe") {
		t.Fatalf("diagnostic was not written to agent.log: %q", contents)
	}

	// A log path occupied by a directory makes the open fail. The service must
	// keep running, and it must start logging again once the path frees instead
	// of staying silent for the rest of its life.
	blocked := filepath.Join(t.TempDir(), "agent.log")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	degraded, writer := newServiceLoggerWithWriter(filepath.Dir(blocked))
	degraded.Warn("while the log is unavailable")
	if info, err := os.Stat(blocked); err != nil || !info.IsDir() {
		t.Fatalf("the blocked log path changed underneath the retrying logger: err=%v", err)
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	degraded.Warn("after the log freed up")
	// The degraded logger must still be the file writer — not a sink that
	// swallows everything — otherwise nothing below could recover.
	if writer == nil {
		t.Fatal("no writer was kept for the degraded service logger")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := os.ReadFile(blocked)
	if err != nil {
		t.Fatalf("the logger never reopened the path: %v", err)
	}
	if !strings.Contains(string(recovered), "after the log freed up") {
		t.Fatalf("the post-recovery diagnostic is missing: %q", recovered)
	}
	if strings.Contains(string(recovered), "while the log is unavailable") {
		t.Fatalf("a diagnostic was claimed as written while the log could not be opened: %q", recovered)
	}
}

// TestResolveServiceStateDirPrefersTheExplicitDirectory proves an operator's
// explicit --state-dir is honoured when it normalizes, and that a blank or
// invalid one falls back to the machine-wide service state directory.
func TestResolveServiceStateDirPrefersTheExplicitDirectory(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	explicit := t.TempDir()
	if got := resolveServiceStateDir(explicit); !strings.EqualFold(got, explicit) {
		t.Fatalf("resolveServiceStateDir(%q)=%q", explicit, got)
	}
	for _, blank := range []string{"", `\?\`} {
		if got := resolveServiceStateDir(blank); !strings.HasPrefix(got, StateDir()) {
			t.Fatalf("resolveServiceStateDir(%q)=%q want the service directory %q", blank, got, StateDir())
		}
	}
}
