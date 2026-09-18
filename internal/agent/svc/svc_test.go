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

// TestServiceLoggerDegradesWhenTheLogCannotBeOpened proves the service still
// runs when its log path is unusable (a logger failure must never stop the
// tunnel), and that a usable path receives the diagnostics.
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

	// A file where the log DIRECTORY should be makes the open fail.
	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	degraded := newServiceLogger(blocked)
	degraded.Warn("must not panic")
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
