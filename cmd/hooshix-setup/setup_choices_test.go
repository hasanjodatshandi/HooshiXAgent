//go:build windows

package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
)

func clearAddressEnvironment(t *testing.T) {
	t.Helper()
	// An empty value is treated as unset, which is exactly how a developer
	// shell that exported nothing must behave.
	t.Setenv(envTunnelURL, "")
	t.Setenv(envPanelURL, "")
}

func TestCollectInstallChoicesAcceptsTheShippedDefaultsWhenNothingIsTyped(t *testing.T) {
	clearAddressEnvironment(t)
	var out bytes.Buffer
	choices, err := collectInstallChoices(&out, bufio.NewReader(strings.NewReader("\n\n")), true)
	if err != nil {
		t.Fatal(err)
	}
	if choices.tunnelURL != defaultTunnelURL || choices.panelURL != defaultPanelURL {
		t.Fatalf("defaults were not offered: %+v", choices)
	}
	if choices.tunnelGiven {
		t.Fatal("an accepted default is not an operator answer and must not overwrite a paired gateway")
	}
	transcript := out.String()
	if !strings.Contains(transcript, "Tunnel server URL ["+defaultTunnelURL+"]") {
		t.Fatalf("the tunnel prompt must show its default, got %q", transcript)
	}
	if !strings.Contains(transcript, "Panel server URL ["+defaultPanelURL+"]") {
		t.Fatalf("the panel prompt must show the new domain default, got %q", transcript)
	}
}

func TestCollectInstallChoicesTakesTheAddressesTheOperatorGave(t *testing.T) {
	clearAddressEnvironment(t)
	var out bytes.Buffer
	choices, err := collectInstallChoices(&out,
		bufio.NewReader(strings.NewReader("wss://lab.example/agent/v1/connect\n-\n")), true)
	if err != nil {
		t.Fatal(err)
	}
	if choices.tunnelURL != "wss://lab.example/agent/v1/connect" || !choices.tunnelGiven {
		t.Fatalf("typed tunnel lost: %+v", choices)
	}
	if choices.panelURL != "" {
		t.Fatalf("declining enrollment must yield an empty panel URL, got %q", choices.panelURL)
	}
}

func TestCollectInstallChoicesRejectsAnAddressItCannotUse(t *testing.T) {
	clearAddressEnvironment(t)
	var out bytes.Buffer
	_, err := collectInstallChoices(&out,
		bufio.NewReader(strings.NewReader("https://tunnel.hooshix-agent.ir\nnot a url\nhttp://again\n")), true)
	if err == nil {
		t.Fatal("Setup accepted a tunnel address that is not a Gateway WSS origin")
	}
	if !strings.Contains(err.Error(), "Tunnel server URL") {
		t.Fatalf("error %q does not name the prompt that failed", err)
	}
	if !strings.Contains(out.String(), "that address was not accepted") {
		t.Fatalf("a rejected answer must be explained, got %q", out.String())
	}
	if strings.Contains(out.String(), "Panel server URL") {
		t.Fatal("Setup must not move on to the panel prompt while the tunnel address is unresolved")
	}

	t.Setenv(envPanelURL, "https://panel.example/path")
	if _, err := collectInstallChoices(&out, bufio.NewReader(strings.NewReader("\n")), true); err == nil {
		t.Fatal(envPanelURL + " accepted a URL with a path")
	} else if !strings.Contains(err.Error(), envPanelURL) {
		t.Fatalf("error %q does not name the variable at fault", err)
	}
}

func TestCollectInstallChoicesNeverPromptsWithoutAConsole(t *testing.T) {
	clearAddressEnvironment(t)
	var out bytes.Buffer
	// A reader with no input at all: an unattended install must resolve from
	// the environment and the defaults without consuming it.
	t.Setenv(envTunnelURL, "wss://tunnel.example/agent/v1/connect")
	choices, err := collectInstallChoices(&out, bufio.NewReader(strings.NewReader("")), false)
	if err != nil {
		t.Fatal(err)
	}
	if choices.tunnelURL != "wss://tunnel.example/agent/v1/connect" || !choices.tunnelGiven {
		t.Fatalf("HOOSHIX_TUNNEL_URL was ignored: %+v", choices)
	}
	if choices.panelURL != "" {
		t.Fatalf("an install with no console cannot approve a device code, got %q", choices.panelURL)
	}
	if !strings.Contains(out.String(), "no console") {
		t.Fatalf("the reason enrollment was skipped must be printed, got %q", out.String())
	}
}

func TestRelocateRedirectsTheSettingsFileAndKeepsItsContents(t *testing.T) {
	clearAddressEnvironment(t)
	stateDir := t.TempDir()
	programDir := t.TempDir()
	paired := `{"version":1,"update_channel":"stable","gateway_url":"wss://paired.example/agent/v1/connect","device_id":"device-setup-000001"}` + "\n"
	if err := os.WriteFile(filepath.Join(stateDir, settingsFileName), []byte(paired), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := relocateSettingsToInstallDir(&out, stateDir, programDir); err != nil {
		if strings.Contains(err.Error(), "validate settings directory") {
			t.Skipf("this machine's temp directory cannot host an installation directory: %v", err)
		}
		t.Fatal(err)
	}

	target := filepath.Join(programDir, settingsFileName)
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("the settings file did not land beside the program: %v", err)
	}
	if string(data) != paired {
		t.Fatalf("relocation changed the settings bytes: %q", data)
	}
	if _, err := os.Stat(filepath.Join(stateDir, settingsFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the superseded copy is still what the Agent would read: %v", err)
	}
	config, err := agent.LoadConfig(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if config.DeviceID != "device-setup-000001" {
		t.Fatalf("the redirected settings file was not read back: %+v", config)
	}
}

func TestApplyTunnelURLOnlyOverwritesWhatTheOperatorAskedFor(t *testing.T) {
	stateDir := t.TempDir()
	if err := agent.MutateConfig(stateDir, func(config *agent.Config) error {
		config.GatewayURL = "wss://paired.example/agent/v1/connect"
		config.DeviceID = "device-setup-000002"
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := applyTunnelURL(stateDir, installChoices{tunnelURL: defaultTunnelURL}); err != nil {
		t.Fatal(err)
	}
	config, err := agent.LoadConfig(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if config.GatewayURL != "wss://paired.example/agent/v1/connect" {
		t.Fatalf("an accepted default overwrote a paired gateway: %q", config.GatewayURL)
	}

	if err := applyTunnelURL(stateDir, installChoices{tunnelURL: defaultTunnelURL, tunnelGiven: true}); err != nil {
		t.Fatal(err)
	}
	config, err = agent.LoadConfig(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if config.GatewayURL != defaultTunnelURL || config.DeviceID != "device-setup-000002" {
		t.Fatalf("the operator's address did not reach the settings file: %+v", config)
	}
}

func TestPreserveRedirectedSettingsMovesTheFileBackForKeepConfig(t *testing.T) {
	stateDir := t.TempDir()
	programDir := t.TempDir()
	target := filepath.Join(programDir, settingsFileName)
	if err := agent.WriteSettingsLocation(stateDir, target); err != nil {
		if strings.Contains(err.Error(), "validate settings directory") {
			t.Skipf("this machine's temp directory cannot host an installation directory: %v", err)
		}
		t.Fatal(err)
	}
	paired := `{"version":1,"update_channel":"stable","gateway_url":"wss://tunnel.hooshix-agent.ir/agent/v1/connect","device_id":"device-setup-000003"}` + "\n"
	if err := os.WriteFile(target, []byte(paired), 0o644); err != nil {
		t.Fatal(err)
	}
	// The uninstaller only writes into a tree the Agent itself claimed.
	if err := os.WriteFile(filepath.Join(stateDir, stateMarkerName), []byte(stateMarkerVersion+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := preserveRedirectedSettings(stateDir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(stateDir, settingsFileName))
	if err != nil {
		t.Fatalf("the settings file was not kept: %v", err)
	}
	if string(data) != paired {
		t.Fatalf("keeping the settings file changed its bytes: %q", data)
	}
	if _, err := os.Stat(filepath.Join(stateDir, settingsLocationFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the pointer outlived the directory it pointed at: %v", err)
	}
}

func TestPreserveRedirectedSettingsIgnoresInstallsThatWereNeverRedirected(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, settingsFileName), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := preserveRedirectedSettings(stateDir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(stateDir, settingsFileName))
	if err != nil || string(data) != "{}\n" {
		t.Fatalf("an unredirected install lost its settings: %q (%v)", data, err)
	}

	// A pointer the Agent would never have obeyed is only a stray record.
	if err := os.WriteFile(filepath.Join(stateDir, settingsLocationFile), []byte("relative/config.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := preserveRedirectedSettings(stateDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, settingsLocationFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an unusable pointer survived the uninstall")
	}
	if data, err := os.ReadFile(filepath.Join(stateDir, settingsFileName)); err != nil || string(data) != "{}\n" {
		t.Fatalf("the kept settings file was disturbed: %q (%v)", data, err)
	}
}
