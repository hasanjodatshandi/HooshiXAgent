//go:build windows

package tray

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadinessFromStateMapsEveryPhase pins the icon-color mapping: every
// phase/state pair the service can write to status.json must map to the
// intended readiness color (green = connected, yellow = degraded, red =
// terminal).
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
		{"pending_config", TrayState{Phase: "pending_config"}, readinessYellow},
		{"terminal", TrayState{Phase: "terminal"}, readinessRed},
		{"service unknown (SCM query failed)", TrayState{Phase: "service:unknown"}, readinessYellow},
		{"service stopped", TrayState{Phase: "service:stopped"}, readinessYellow},
		{"exiting", TrayState{Phase: "exiting"}, readinessYellow},
		{"empty snapshot", TrayState{}, readinessYellow},
	}
	for _, test := range cases {
		if got := readinessFromState(test.state); got != test.want {
			t.Errorf("%s: readiness=%v want=%v (state=%+v)", test.name, got, test.want, test.state)
		}
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
