//go:build windows

package tray

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadinessFromStateMapsEveryPhase pins the icon-color mapping: every
// phase/state pair the service can write must map to the intended readiness
// color (green = connected, yellow = service up but not connected, red =
// terminal failure or no service).
func TestReadinessFromStateMapsEveryPhase(t *testing.T) {
	cases := []struct {
		name  string
		state TrayState
		want  readiness
	}{
		{"running+connected (status.json phase)", TrayState{Phase: "running", State: "connected"}, readinessGreen},
		{"service running+connected (SCM suffix)", TrayState{Phase: "service:running", State: "connected"}, readinessGreen},
		{"running+connecting", TrayState{Phase: "running", State: "connecting"}, readinessYellow},
		{"running+authenticating", TrayState{Phase: "running", State: "authenticating"}, readinessYellow},
		{"running+degraded", TrayState{Phase: "running", State: "degraded"}, readinessYellow},
		{"reconnecting", TrayState{Phase: "reconnecting"}, readinessYellow},
		// The owner's actual situation: service running, device unpaired.
		// Yellow (not red) says "the service is up, the tunnel is not".
		{"pending_config (service up, unpaired)", TrayState{Phase: "pending_config", State: "init"}, readinessYellow},
		{"terminal", TrayState{Phase: "terminal"}, readinessRed},
		// No service: red, so it cannot be confused with an unpaired agent.
		// These two used to be yellow, contradicting this file's own
		// documented "red = ... the service being unreachable" and making the
		// reported operator confusion ("yellow means the service failed")
		// unavoidable.
		{"service unknown (SCM query failed)", TrayState{Phase: "service:unknown"}, readinessRed},
		{"service stopped", TrayState{Phase: "service:stopped"}, readinessRed},
		{"exiting", TrayState{Phase: "exiting"}, readinessYellow},
		{"empty snapshot", TrayState{}, readinessYellow},
	}
	for _, test := range cases {
		if got := readinessFromState(test.state); got != test.want {
			t.Errorf("%s: readiness=%v want=%v (state=%+v)", test.name, got, test.want, test.state)
		}
	}
}

// TestStatusDisplayTextDistinguishesServiceFromPairing pins the operator-facing
// text, which is what actually misled the owner: the unpaired agent rendered as
// the bare internal token "init". A service that is not running and a service
// that runs unpaired must never read the same.
func TestStatusDisplayTextDistinguishesServiceFromPairing(t *testing.T) {
	cases := []struct {
		name  string
		state TrayState
		want  string
	}{
		{"unpaired agent (owner's machine)", TrayState{Phase: "pending_config", State: "init"}, "not paired yet (service running)"},
		{"service stopped", TrayState{Phase: "service:stopped", State: "connected"}, "service stopped"},
		{"service unknown", TrayState{Phase: "service:unknown", State: "status-unavailable"}, "service status unavailable"},
		{"connected agent phase", TrayState{Phase: "running", State: "connected"}, "connected"},
		{"connected service phase", TrayState{Phase: "service:running", State: "connected"}, "connected"},
		{"running, tunnel still starting", TrayState{Phase: "running", State: "init"}, "starting"},
		{"terminal", TrayState{Phase: "terminal", State: "shutdown"}, "stopped (error)"},
		{"agent revoked", TrayState{Phase: "running", State: "revoked"}, "revoked by gateway"},
		{"reconnecting", TrayState{Phase: "reconnecting", State: "connecting"}, "reconnecting"},
		{"exiting", TrayState{Phase: "exiting"}, "exiting"},
	}
	for _, test := range cases {
		if got := statusDisplayText(test.state); got != test.want {
			t.Errorf("%s: text=%q want=%q (state=%+v)", test.name, got, test.want, test.state)
		}
	}
	// The regression that started this: no raw internal state token may reach
	// the menu for the unpaired agent.
	if got := statusDisplayText(TrayState{Phase: "pending_config", State: "init"}); got == "init" {
		t.Errorf("unpaired agent still renders the raw state token: %q", got)
	}
}

// TestMergeAgentStatusAdoptsAgentPhaseWhileRunning proves the tray keeps the
// agent's own phase (so "pending_config" can reach the menu) but drops it as
// soon as SCM says the service is not running, because a stopped service
// leaves a stale status.json behind.
func TestMergeAgentStatusAdoptsAgentPhaseWhileRunning(t *testing.T) {
	unpaired := TrayState{Phase: "pending_config", State: "init"}

	running := mergeAgentStatus("running", unpaired, true)
	if running.Phase != "pending_config" || running.State != "init" {
		t.Fatalf("running service must adopt the agent phase: %+v", running)
	}
	if got := statusDisplayText(running); got != "not paired yet (service running)" {
		t.Fatalf("unpaired service text=%q", got)
	}

	stopped := mergeAgentStatus("stopped", unpaired, true)
	if stopped.Phase != "service:stopped" {
		t.Fatalf("a stopped service must not inherit a stale agent phase: %+v", stopped)
	}
	if got := statusDisplayText(stopped); got != "service stopped" {
		t.Fatalf("stopped service text=%q", got)
	}
	if readinessFromState(stopped) != readinessRed {
		t.Fatalf("stopped service must be red, got %v", readinessFromState(stopped))
	}

	missing := mergeAgentStatus("running", TrayState{}, false)
	if missing.Phase != "service:running" {
		t.Fatalf("missing status.json must keep the service phase: %+v", missing)
	}
	if got := statusDisplayText(missing); got != "unknown" {
		t.Fatalf("missing status.json text=%q", got)
	}
}

// TestIsUpAndDownStates pins the transition helper semantics used by the
// balloon and flash triggers.
func TestIsUpAndDownStates(t *testing.T) {
	up := TrayState{Phase: "running", State: "connected"}
	if !isUpState(up) {
		t.Fatalf("connected running state must be up: %+v", up)
	}
	if isDownState(up) {
		t.Fatalf("connected running state must not be down: %+v", up)
	}
	down := TrayState{Phase: "running", State: "connecting"}
	if isUpState(down) || !isDownState(down) {
		t.Fatalf("running but not connected must be down: %+v", down)
	}
	reconnecting := TrayState{Phase: "reconnecting"}
	if isUpState(reconnecting) || !isDownState(reconnecting) {
		t.Fatalf("reconnecting must be down: %+v", reconnecting)
	}
	// The unpaired agent is down: the tray must still say so, exactly as it did
	// when this state arrived as "service:running". Enumerating phase suffixes
	// missed the agent's own "pending_config" and classified it as healthy,
	// which would have left the owner's yellow icon unexplained.
	unpaired := TrayState{Phase: "pending_config", State: "init"}
	if isUpState(unpaired) || !isDownState(unpaired) {
		t.Fatalf("unpaired agent must be down: %+v", unpaired)
	}
	if isDownState(TrayState{Phase: "exiting"}) || isDownState(TrayState{}) {
		t.Fatal("exiting and pre-first-poll snapshots must not be down")
	}
}

// TestSettingsRoundTrip pins the persisted balloon preference: the store
// defaults to enabled, a set persists, and reload sees the stored value.
func TestSettingsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := newSettingsStore(dir)
	if !store.enabled() {
		t.Fatal("default preference must be enabled")
	}
	store.setEnabled(false)
	if store.enabled() {
		t.Fatal("value must read back false in the same store")
	}
	reloaded := newSettingsStore(dir)
	if reloaded.enabled() {
		t.Fatal("reloaded store must see the persisted disabled preference")
	}
	reloaded.setEnabled(true)
	if !newSettingsStore(dir).enabled() {
		t.Fatal("re-enabled preference must persist")
	}
}

// TestSettingsCorruptFileFallsBackToDefault proves a damaged settings file
// cannot disable notifications silently.
func TestSettingsCorruptFileFallsBackToDefault(t *testing.T) {
	dir := t.TempDir()
	if err := writeFile(dir, "settings.json", []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	if store := newSettingsStore(dir); !store.enabled() {
		t.Fatal("corrupt settings file must fall back to the enabled default")
	}
}

func writeFile(dir, name string, data []byte) error {
	return os.WriteFile(filepath.Join(dir, name), data, 0o600)
}
