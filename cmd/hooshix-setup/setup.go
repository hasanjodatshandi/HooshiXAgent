//go:build windows

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// payload is the embedded Agent and tray distribution. It is supplied by
// payload_embed.go (release builds, -tags hooshix_release_payload) or by the
// non-release payload_stub.go, so a clean checkout builds without the
// gitignored payload binaries. See scripts/build-setup.ps1.

// installDir is the fixed program directory. It is a var, not a const, only so
// the payload commit/rollback sequence can be exercised against a temporary
// directory in tests; a real install never reassigns it.
var installDir = `C:\Program Files\HooshiXAgent`

const (
	arpKeyPath      = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HooshiXAgent`
	appTitle        = "HooshiX Agent"
	agentBinary     = "hooshix-agent.exe"
	trayBinary      = "hooshix-agent-tray.exe"
	uninstallBinary = "uninstall.exe"
	trayTaskName    = "HooshiXAgentTray"
	// stateDirName is the fixed leaf the service, the uninstaller and the
	// Agent's own ServiceStateDir() all agree on.
	stateDirName = "HooshiXAgent"
	// payloadManifest is embedded next to the payload binaries by
	// scripts/build-setup.ps1 and records their SHA-256 digests. Setup verifies
	// every payload byte against it before anything is written to the install
	// directory, so a truncated or corrupted embed cannot be promoted to
	// C:\Program Files as a silently different executable.
	payloadManifest = "SHA256SUMS"
	// defaultTunnelURL is the Gateway the Agent connects to when the operator
	// does not say otherwise, and defaultPanelURL is the panel Setup enrolls
	// the device against. Both are only defaults: Setup asks, an answer (or the
	// matching HOOSHIX_*_URL variable) wins, and the result is re-editable in
	// the settings file afterwards. `edge` rather than `tunnel`: some networks
	// drop the literal name `tunnel` from DNS answers, and both hostnames proxy
	// to the same Gateway replicas.
	defaultTunnelURL = "wss://edge.hooshix-agent.ir/agent/v1/connect"
	defaultPanelURL  = "https://panel.hooshix-agent.ir"
	envTunnelURL     = "HOOSHIX_TUNNEL_URL"
	envPanelURL      = "HOOSHIX_PANEL_URL"
	// settingsFileName and settingsLocationFile mirror the Agent's own names:
	// the editable settings file, and the file inside the state directory that
	// points at it from somewhere else. They are duplicated here for the same
	// reason stateMarkerName is: the uninstaller must recognise the Agent's
	// state layout without importing its internals.
	settingsFileName     = "config.json"
	settingsLocationFile = "settings_location"
)

var setupVersion = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "setup failed:", err)
		pause()
		os.Exit(1)
	}
	pause()
}

func run() error {
	fmt.Println("=== HooshiX Agent Setup ===")
	if uninstall, keepConfig := promptUninstall(); uninstall {
		args := []string{"--uninstall"}
		if keepConfig {
			args = append(args, keepConfigFlag)
		}
		if err := exec.Command(os.Args[0], args...).Run(); err != nil {
			return fmt.Errorf("uninstall: %w", err)
		}
		return nil
	}
	choices, err := collectInstallChoices(os.Stdout, bufio.NewReader(os.Stdin), stdinIsInteractive())
	if err != nil {
		return err
	}
	stage, err := stagePayload()
	if err != nil {
		return fmt.Errorf("stage binaries: %w", err)
	}
	defer os.RemoveAll(stage)
	manifest, err := embeddedPayloadManifest()
	if err != nil {
		return err
	}
	// The interactive desktop user is only needed for the tray auto-start and
	// for the read+execute ACE that lets that user's tray read status. Neither
	// is required by the product: the service runs under LocalSystem. An
	// unattended/headless host (no interactive logon session at all) must still
	// be installable, so an unresolvable desktop user downgrades the install to
	// SYSTEM+Administrators-only state access instead of failing it.
	interactiveAccount, userErr := interactiveUser()
	if userErr != nil {
		fmt.Println("note: no interactive desktop user resolved:", userErr)
		fmt.Println("      the tray auto-start and its state grant will be skipped; the service does not need them.")
	}

	// An Agent binary already in the install directory means a service
	// registration from an earlier run does too, and the rollback must not
	// unregister what this run did not create.
	replacing := previousInstallationPresent()
	stopPreviousInstallation()
	backups, err := commitStagedPayload(stage, manifest)
	if err != nil {
		return fmt.Errorf("install binaries: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			rollbackInstallation(backups, replacing)
		}
	}()

	if err := installPairingCapability(interactiveAccount); err != nil {
		return fmt.Errorf("install pairing authorization: %w", err)
	}
	// The settings file moves next to the program before the service first
	// reads it, so there is never a window in which the running Agent and the
	// file the operator edits are different files.
	stateDir, err := serviceStateDir()
	if err != nil {
		return fmt.Errorf("resolve the Agent state directory: %w", err)
	}
	if err := relocateSettingsToInstallDir(os.Stdout, stateDir, installDir); err != nil {
		fmt.Println("warning: the settings file could not be moved next to the program:", err)
		fmt.Println("        it stays at", filepath.Join(stateDir, settingsFileName), "and the Agent reads it from there.")
	} else {
		fmt.Println("settings file:", filepath.Join(installDir, settingsFileName))
	}
	if err := applyTunnelURL(stateDir, choices); err != nil {
		fmt.Println("warning: the tunnel address was not written to the settings file:", err)
	}
	if err := runAgentCommand("service", "install"); err != nil {
		return fmt.Errorf("install service: %w", err)
	}
	if err := runAgentCommand("service", "start"); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	if err := waitForServiceRunning(serviceRunningTimeout); err != nil {
		return err
	}

	// Desktop integration is best-effort: the tunnel (service + binaries) is
	// already installed and running at this point, so a tray-task or
	// uninstall-entry failure must only warn, never roll the install back
	// (rolling back here would remove binaries the running service points
	// at and leave a half-installed machine).
	if err := registerTrayTask(interactiveAccount); err != nil {
		fmt.Println("warning: tray auto-start was not registered:", err)
		fmt.Println("        the HooshiX Agent service is installed and running; start the tray manually or re-run setup.")
	}
	if err := registerUninstall(); err != nil {
		fmt.Println("warning: Windows uninstall entry was not registered:", err)
	}
	for _, backup := range backups {
		_ = os.Remove(backup)
	}
	committed = true
	if err := enrollInstalledAgent(choices.panelURL); err != nil {
		fmt.Println("warning: automatic device enrollment did not complete:", err)
		fmt.Println("         the service remains installed; re-run Setup or use the tray pairing page.")
	}
	fmt.Println("done. The HooshiX Agent service and tray are running.")
	return nil
}

func enrollInstalledAgent(serverURL string) error {
	if serverURL == "" {
		fmt.Println("device enrollment skipped; use the tray icon when you are ready.")
		return nil
	}
	if !stdinIsInteractive() {
		return nil
	}
	reader := bufio.NewReader(os.Stdin)
	defaultName, _ := os.Hostname()
	if strings.TrimSpace(defaultName) == "" {
		defaultName = "Windows PC"
	}
	fmt.Printf("Device name [%s]: ", defaultName)
	deviceName, readErr := reader.ReadString('\n')
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readErr
	}
	deviceName = strings.TrimSpace(deviceName)
	if deviceName == "" {
		deviceName = defaultName
	}
	stateDir, err := serviceStateDir()
	if err != nil {
		return err
	}
	started, err := agent.StartServiceEnrollment(stateDir, serverURL, deviceName)
	if err != nil {
		return err
	}
	fmt.Printf("\nApprove device code %s at:\n%s\n", started.UserCode, started.VerificationURI)
	if err := openEnrollmentBrowser(started.VerificationURI); err != nil {
		fmt.Println("note: the approval page could not be opened automatically; copy the URL above:", err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, started.ExpiresAt)
	if err != nil {
		return errors.New("Agent service returned an invalid enrollment expiry")
	}
	for time.Now().Before(expiresAt) {
		claimed, claimErr := agent.ClaimServiceEnrollment(stateDir)
		if claimErr != nil {
			return claimErr
		}
		if claimed.State == "claimed" {
			fmt.Printf("device %s enrolled successfully.\n", claimed.DeviceID)
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return errors.New("device approval expired; start enrollment again")
}

// installChoices are the two server addresses Setup collects: the Gateway the
// Agent dials, and the panel the device enrolls against.
type installChoices struct {
	tunnelURL string
	panelURL  string
	// tunnelGiven marks an answer the operator actually supplied (typed or via
	// HOOSHIX_TUNNEL_URL). Without it a default must never overwrite a gateway
	// a previous pairing already recorded.
	tunnelGiven bool
}

func stdinIsInteractive() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// collectInstallChoices resolves the tunnel and panel addresses before anything
// is written to the machine, so a mistyped address fails an install that has not
// happened yet instead of leaving a service that cannot connect.
//
// Precedence: an explicit HOOSHIX_*_URL, then a typed answer, then the shipped
// default. A closed stdin (unattended, CI, or a silent install) never prompts,
// which is what keeps the service-install smoke from hanging on a console that
// is not there.
func collectInstallChoices(out io.Writer, reader *bufio.Reader, interactive bool) (installChoices, error) {
	choices := installChoices{tunnelURL: defaultTunnelURL, panelURL: defaultPanelURL}
	if value, ok := trimmedEnv(os.LookupEnv, envTunnelURL); ok {
		if err := agent.ValidateGatewayURL(value); err != nil {
			return choices, fmt.Errorf("%s: %w", envTunnelURL, err)
		}
		choices.tunnelURL, choices.tunnelGiven = value, true
	}
	if value, ok := trimmedEnv(os.LookupEnv, envPanelURL); ok {
		if err := validatePanelOrigin(value); err != nil {
			return choices, fmt.Errorf("%s: %w", envPanelURL, err)
		}
		choices.panelURL = value
	}
	if !interactive {
		// No console: an operator who did set HOOSHIX_PANEL_URL still cannot
		// approve a device code here, so enrollment is declined, not guessed.
		fmt.Fprintln(out, "no console: using the default tunnel address and skipping device enrollment.")
		choices.panelURL = ""
		return choices, nil
	}
	if choices.tunnelGiven {
		fmt.Fprintf(out, "Tunnel server URL from %s: %s\n", envTunnelURL, choices.tunnelURL)
	} else {
		value, given, err := promptValue(out, reader, "Tunnel server URL", choices.tunnelURL, agent.ValidateGatewayURL)
		if err != nil {
			return choices, err
		}
		choices.tunnelURL, choices.tunnelGiven = value, given
	}
	if choices.panelURL != "" && choices.panelURL != defaultPanelURL {
		fmt.Fprintf(out, "Panel server URL from %s: %s\n", envPanelURL, choices.panelURL)
	} else {
		fmt.Fprintln(out, "Press Enter to use the default; type - to pair this device later from the tray.")
		// "-" is an answer, not an address, so it has to be accepted before the
		// origin rule runs.
		acceptDecline := func(raw string) error {
			if raw == "-" {
				return nil
			}
			return validatePanelOrigin(raw)
		}
		value, _, err := promptValue(out, reader, "Panel server URL", choices.panelURL, acceptDecline)
		if err != nil {
			return choices, err
		}
		if value == "-" {
			value = ""
		}
		choices.panelURL = value
	}
	return choices, nil
}

// promptValue asks once per answer and re-asks on invalid input. An empty answer
// takes the default, so accepting both defaults is two Enter presses.
func promptValue(out io.Writer, reader *bufio.Reader, label, fallback string, validate func(string) error) (value string, given bool, err error) {
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Fprintf(out, "%s [%s]: ", label, fallback)
		raw, readErr := reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return "", false, readErr
		}
		answer := strings.TrimSpace(raw)
		if answer == "" {
			return fallback, false, nil
		}
		if validate == nil {
			return answer, true, nil
		}
		if validateErr := validate(answer); validateErr != nil {
			fmt.Fprintln(out, "  that address was not accepted:", validateErr)
			continue
		}
		return answer, true, nil
	}
	return "", false, fmt.Errorf("%s: no valid address was entered", label)
}

// validatePanelOrigin mirrors the enrollment client's own rule: an origin only,
// HTTPS everywhere except a loopback test server. Catching it here means Setup
// fails before the service is installed rather than after.
func validatePanelOrigin(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return errors.New("the panel URL must be an origin without credentials, path, query, or fragment")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if parsed.Scheme != "http" || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
		return errors.New("the panel URL must use HTTPS (HTTP is only allowed for an IP/localhost test server)")
	}
	return nil
}

func trimmedEnv(lookup func(string) (string, bool), name string) (string, bool) {
	value, ok := lookup(name)
	value = strings.TrimSpace(value)
	return value, ok && value != ""
}

// relocateSettingsToInstallDir moves the editable settings file from the service
// state directory to the installation directory, where the operator can find it
// beside the program, and leaves the pointer the Agent follows behind.
//
// The state directory's copy wins when both exist: it is what the previously
// installed Agent was actually running, while a copy left in Program Files can
// only be debris from an interrupted earlier install.
func relocateSettingsToInstallDir(out io.Writer, stateDir, targetDir string) error {
	source := filepath.Join(stateDir, settingsFileName)
	target := filepath.Join(targetDir, settingsFileName)
	data, err := os.ReadFile(source)
	switch {
	case err == nil:
		if existing, statErr := os.Stat(target); statErr == nil && !existing.IsDir() {
			fmt.Fprintln(out, "note: both a state and an install-directory settings file exist; keeping the state directory's contents.")
		}
	case errors.Is(err, os.ErrNotExist):
		data = nil
	default:
		return fmt.Errorf("read the current settings file: %w", err)
	}
	if err := agent.WriteSettingsLocation(stateDir, target); err != nil {
		return fmt.Errorf("record the settings location: %w", err)
	}
	if data != nil {
		if err := os.WriteFile(target, data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", filepath.Base(target), err)
		}
		// The pointer now selects the install-directory copy, so the state
		// directory's copy is debris. Deleting it is best-effort: leaving it
		// cannot misdirect the Agent, which no longer reads that path.
		if err := os.Remove(source); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(out, "note: the superseded settings copy is still in the state directory:", err)
		}
	}
	return nil
}

// applyTunnelURL writes the Gateway address the operator chose into the settings
// file, so the file beside the program is the whole story of where this Agent
// connects. An answer nobody gave must not overwrite a paired gateway.
func applyTunnelURL(stateDir string, choices installChoices) error {
	return agent.MutateConfig(stateDir, func(config *agent.Config) error {
		if !choices.tunnelGiven && strings.TrimSpace(config.GatewayURL) != "" {
			return nil
		}
		config.GatewayURL = choices.tunnelURL
		return nil
	})
}

func openEnrollmentBrowser(target string) error {
	command := exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	if err := command.Start(); err != nil {
		return fmt.Errorf("open browser: %w", err)
	}
	return nil
}

// embeddedPayloadManifest returns the SHA-256SUMS document the distribution
// build recorded next to the payload binaries. Staging and the post-commit
// verification both read it through here so they can never disagree.
func embeddedPayloadManifest() (string, error) {
	data, err := fs.ReadFile(payload, "payload/"+payloadManifest)
	if err != nil {
		return "", fmt.Errorf("read embedded payload manifest: %w", err)
	}
	return string(data), nil
}

func stagePayload() (string, error) {
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return "", err
	}
	stage, err := os.MkdirTemp(installDir, ".setup-")
	if err != nil {
		return "", err
	}
	manifest, err := embeddedPayloadManifest()
	if err != nil {
		os.RemoveAll(stage)
		return "", err
	}
	for _, name := range []string{agentBinary, trayBinary} {
		data, readErr := fs.ReadFile(payload, "payload/"+name)
		if readErr != nil {
			os.RemoveAll(stage)
			return "", readErr
		}
		if verifyErr := verifyPayloadDigest(string(manifest), name, data); verifyErr != nil {
			os.RemoveAll(stage)
			return "", verifyErr
		}
		if writeErr := os.WriteFile(filepath.Join(stage, name), data, 0o755); writeErr != nil {
			os.RemoveAll(stage)
			return "", writeErr
		}
	}
	self, err := os.Executable()
	if err != nil {
		os.RemoveAll(stage)
		return "", err
	}
	data, err := os.ReadFile(self)
	if err != nil {
		os.RemoveAll(stage)
		return "", err
	}
	if err := os.WriteFile(filepath.Join(stage, uninstallBinary), data, 0o755); err != nil {
		os.RemoveAll(stage)
		return "", err
	}
	return stage, nil
}

// verifyPayloadDigest checks one embedded payload binary against its entry in
// the embedded SHA256SUMS manifest. A missing manifest entry and a digest
// mismatch are both fatal: the whole point of installing from an embedded
// payload is that the bytes written to the install directory are the bytes the
// distribution build produced.
func verifyPayloadDigest(manifest, name string, data []byte) error {
	expected, err := manifestDigest(manifest, name)
	if err != nil {
		return err
	}
	actual := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(actual[:]), expected) {
		return fmt.Errorf("embedded %s does not match the embedded %s manifest (%s); refusing to install", name, payloadManifest, expected)
	}
	return nil
}

// manifestDigest returns the lower-case SHA-256 recorded for name in a
// sha256sum-compatible manifest ("<digest>  <name>", optional leading '*' for
// binary mode). Lines without a digest/name pair are ignored.
func manifestDigest(manifest, name string) (string, error) {
	for _, line := range strings.Split(manifest, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		entry := strings.TrimPrefix(fields[len(fields)-1], "*")
		if entry == name || entry == "./"+name {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("embedded %s manifest has no entry for %s; refusing to install", payloadManifest, name)
}

// payloadRenameTimeout bounds how long a payload file is coaxed into or out of
// the install directory. `service stop` only asks SCM to stop the Agent, and a
// filter driver or indexer can hold a just-replaced executable for a moment, so
// a single rename attempt turns an upgrade that would have succeeded into a
// failed install. Uninstall already waits this long; the install path must not
// be stricter than the path that undoes it.
const payloadRenameTimeout = 10 * time.Second

// renameIntoPlace retries os.Rename until it succeeds or the budget runs out.
// A failed rename leaves both operands untouched, so retrying is always safe.
func renameIntoPlace(source, target string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := os.Rename(source, target)
		if err == nil || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func commitStagedPayload(stage, manifest string) (map[string]string, error) {
	backups := make(map[string]string)
	for _, name := range []string{agentBinary, trayBinary, uninstallBinary} {
		target := filepath.Join(installDir, name)
		staged := filepath.Join(stage, name)
		stagedData, err := os.ReadFile(staged)
		if err != nil {
			rollbackFiles(backups)
			return nil, fmt.Errorf("read staged %s: %w", name, err)
		}
		backup := target + ".previous"
		_ = os.Remove(backup)
		if _, err := os.Stat(target); err == nil {
			if err := renameIntoPlace(target, backup, payloadRenameTimeout); err != nil {
				rollbackFiles(backups)
				return nil, fmt.Errorf("move aside %s (is the agent or tray still running?): %w", name, err)
			}
			backups[target] = backup
		}
		if err := renameIntoPlace(staged, target, payloadRenameTimeout); err != nil {
			rollbackFiles(backups)
			return nil, fmt.Errorf("move %s into place: %w", name, err)
		}
		if _, existed := backups[target]; !existed {
			backups[target] = ""
		}
		// Verify the deployed bytes actually match the payload. Windows can
		// report success while an antivirus or filter driver silently reverts
		// or replaces a just-written executable; a silent mismatch here means
		// the service would keep running the previous (possibly vulnerable)
		// build while setup prints "done".
		installed, err := os.ReadFile(target)
		if err != nil {
			rollbackFiles(backups)
			return nil, fmt.Errorf("verify installed %s: %w", name, err)
		}
		if !bytes.Equal(installed, stagedData) {
			rollbackFiles(backups)
			return nil, fmt.Errorf("installed %s does not match the payload (an antivirus or policy may be reverting the file); aborting", name)
		}
		// The comparison above only proves Setup wrote what it staged, and a
		// staged file that drifted from the build after staging satisfies it.
		// The manifest is the distribution build's own record of each binary, so
		// the file that is now live is checked against that rather than against
		// a copy of itself. uninstall.exe is this Setup binary copied from
		// itself, so it has no manifest entry to check against.
		if name != uninstallBinary {
			if err := verifyPayloadDigest(manifest, name, installed); err != nil {
				rollbackFiles(backups)
				return nil, fmt.Errorf("installed %s does not match the distribution manifest: %w", name, err)
			}
		}
	}
	return backups, nil
}

// previousInstallationPresent reports whether an Agent binary is already in the
// install directory. It is the same signal stopPreviousInstallation uses to
// decide that a service registration from an earlier run exists, and it must be
// read before commitStagedPayload moves that binary aside.
func previousInstallationPresent() bool {
	_, err := os.Stat(filepath.Join(installDir, agentBinary))
	return err == nil
}

// rollbackInstallation returns the machine to the state it was in before this
// run. The service has to be dealt with before the files: a running Agent holds
// hooshix-agent.exe open, and `service stop` only posts the control request, so
// renaming the previous build back over it fails - and rollbackFiles ignores
// that failure, which would leave the very build this run was aborting in place.
// On a fresh install the registration created moments ago must also be removed,
// or SCM is left with a service pointing at a binary the rollback deletes.
func rollbackInstallation(backups map[string]string, replacing bool) {
	if err := runAgentCommand("service", "stop"); err != nil {
		fmt.Println("note: rollback could not ask the service to stop:", err)
	}
	if err := waitForServiceStopped(serviceStoppedTimeout); err != nil {
		fmt.Println("note: rollback is continuing with the service not fully stopped:", err)
	}
	if !replacing {
		if err := runAgentCommand("service", "uninstall"); err != nil {
			fmt.Println("note: rollback could not remove the service registration:", err)
		}
	}
	rollbackFiles(backups)
	if replacing {
		// The previous build is back in place, so put it running again: a failed
		// upgrade must not also cost the operator their tunnel.
		if err := runAgentCommand("service", "start"); err != nil {
			fmt.Println("note: the previous Agent build is restored but its service did not start:", err)
			fmt.Println("        start it with: sc start", agent.WindowsServiceName)
		}
	}
}

func rollbackFiles(backups map[string]string) {
	for target, backup := range backups {
		_ = os.Remove(target)
		if backup != "" {
			_ = os.Rename(backup, target)
		}
	}
}

func runAgentCommand(args ...string) error {
	output, err := runAgentCommandOutput(args...)
	if err != nil {
		return fmt.Errorf("%v: %w: %s", args, err, strings.TrimSpace(output))
	}
	return nil
}

// agentCommand runs the installed Agent binary with the given arguments and
// returns its combined output with the execution error. It is a var so the
// rollback sequence - which service commands, in which order, relative to the
// file renames - can be asserted without an SCM to talk to.
var agentCommand = func(args ...string) (string, error) {
	output, err := exec.Command(filepath.Join(installDir, agentBinary), args...).CombinedOutput()
	return string(output), err
}

// runAgentCommandOutput runs the installed Agent binary and returns its
// combined output together with the execution error, so callers that must
// inspect what the Agent reported (service status) do not have to re-implement
// the invocation.
func runAgentCommandOutput(args ...string) (string, error) {
	return agentCommand(args...)
}

// serviceStoppedTimeout bounds how long a rollback waits for SCM to report the
// service no longer running before renaming files over it anyway.
const serviceStoppedTimeout = 15 * time.Second

// waitForServiceStopped polls the Agent's own `service status` until the service
// can no longer be holding its executable open. An unanswerable query counts as
// stopped: no binary, or no registration, means no handle.
func waitForServiceStopped(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	last := "no status was observed"
	for {
		output, err := runAgentCommandOutput("service", "status")
		if err != nil {
			return nil
		}
		last = strings.TrimSpace(output)
		switch last {
		case "running", "start-pending", "continue-pending":
		default:
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("the %s service is still %s after %s", agent.WindowsServiceName, last, timeout)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// serviceRunningTimeout bounds how long setup waits for SCM to report the
// service Running after a successful start request.
const serviceRunningTimeout = 30 * time.Second

// waitForServiceRunning polls the Agent's own `service status` until SCM
// reports Running. Setup starts the service and previously printed "done. The
// HooshiX Agent service and tray are running." without ever observing that: a
// service that starts and immediately exits (Agent initialization failure —
// the service exits non-zero on purpose so SCM recovery can act) would be
// reported as a running product. The bounded wait turns that into an install
// failure the operator can act on.
func waitForServiceRunning(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	last := "no status was observed"
	for {
		output, err := runAgentCommandOutput("service", "status")
		if err != nil {
			last = strings.TrimSpace(output + " " + err.Error())
		} else {
			last = strings.TrimSpace(output)
			if strings.HasSuffix(last, "running") {
				return nil
			}
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("the %s service did not report Running within %s (last SCM status: %s); inspect `sc.exe query %s` and the Agent log in its state directory",
				agent.WindowsServiceName, timeout, last, agent.WindowsServiceName)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// stopPreviousInstallation stops whatever from a previous installation still
// holds the payload files open, so the staged replacement below can rename
// them. It is deliberately tolerant: on a fresh machine there is no service
// and no process to stop, which is not an error.
func stopPreviousInstallation() {
	if previousInstallationPresent() {
		if err := runAgentCommand("service", "stop"); err != nil {
			fmt.Println("note: stopping previous service:", err)
		}
		// The rename below cannot land while the service still holds
		// hooshix-agent.exe, and `service stop` only posts the request, so wait
		// for the state SCM reports instead of guessing a duration.
		if err := waitForServiceStopped(serviceStoppedTimeout); err != nil {
			fmt.Println("note: the previous service is still running:", err)
		}
	}
	_ = exec.Command("schtasks.exe", "/End", "/TN", trayTaskName).Run()
	killProcessByName(trayBinary)
	killProcessByName(agentBinary)
	time.Sleep(time.Second)
}

func killProcessByName(name string) { _ = exec.Command("taskkill.exe", "/F", "/IM", name).Run() }

var (
	wtsapi32DLL = windows.NewLazySystemDLL("wtsapi32.dll")
	wtsQuery    = wtsapi32DLL.NewProc("WTSQuerySessionInformationW")
)

const (
	wtsUserName   = 5 // WTSUserName
	wtsDomainName = 7 // WTSDomainName
	wtsActive     = 0 // WTSActive
)

// interactiveUser returns the account owning the active console session (the
// physical desktop user), not the elevated installer account. It prefers the
// active console session, then falls back to enumerating every WTS session
// for any active one with a logged-on user (covers RDS/multi-session hosts
// where WTSGetActiveConsoleSessionId reports the services session). The
// returned errors are static: a nil error is never wrapped.
func interactiveUser() (string, error) {
	if user := querySessionUser(windows.WTSGetActiveConsoleSessionId()); user != "" {
		return user, nil
	}
	if user := firstActiveSessionUser(); user != "" {
		return user, nil
	}
	return "", errors.New("no logged-on desktop user found in any active session")
}

func querySessionUser(sessionID uint32) string {
	if sessionID == 0 || sessionID == ^uint32(0) {
		return ""
	}
	user := querySessionString(sessionID, wtsUserName)
	if user == "" {
		return ""
	}
	domain := querySessionString(sessionID, wtsDomainName)
	if domain != "" {
		return domain + `\` + user
	}
	return user
}

func querySessionString(sessionID uint32, infoClass uintptr) string {
	var buffer *uint16
	var length uint32
	result, _, _ := wtsQuery.Call(0, uintptr(sessionID), infoClass, uintptr(unsafe.Pointer(&buffer)), uintptr(unsafe.Pointer(&length)))
	if result == 0 || buffer == nil {
		return ""
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buffer)))
	return windows.UTF16PtrToString(buffer)
}

// firstActiveSessionUser scans every WTS session for an active one with a
// logged-on user. It is the fallback when the active console session cannot
// be resolved (elevated service contexts, disconnected console, RDS).
func firstActiveSessionUser() string {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil || sessions == nil || count == 0 {
		return ""
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	for _, session := range unsafe.Slice(sessions, count) {
		if session.State != wtsActive {
			continue
		}
		if user := querySessionUser(session.SessionID); user != "" {
			return user
		}
	}
	return ""
}

func registerTrayTask(user string) error {
	if strings.TrimSpace(user) == "" {
		return errors.New("no interactive desktop user was resolved to run the tray")
	}
	// Run as the interactive user without storing their password: schtasks
	// only permits /RU with a password or for the current user with /IT.
	// The logon-trigger task under the console user's own account is
	// created via XML to avoid credential prompts.
	userXML := xmlEscape(user)
	commandXML := xmlEscape(filepath.Join(installDir, trayBinary))
	taskXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>HooshiX Agent tray auto-start at logon</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>%s</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
    </Exec>
  </Actions>
</Task>`, userXML, commandXML)
	// Stage the task XML in a uniquely named temp file: the previous fixed
	// "%TEMP%\hooshix-tray-task.xml" name let any process running as the same
	// account pre-create or replace the file an ELEVATED setup then handed to
	// schtasks.exe (a pre-creation/link attack on a privileged process).
	tempXML, err := stageTaskXML(taskXML)
	if err != nil {
		return err
	}
	defer os.Remove(tempXML)
	// UserId + InteractiveToken in the XML is sufficient. Adding /RU makes
	// schtasks prompt for that user's password even though none is required.
	args := []string{"/Create", "/F", "/TN", trayTaskName, "/XML", tempXML}
	output, err := exec.Command("schtasks.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks create: %w: %s", err, strings.TrimSpace(string(output)))
	}
	output, err = exec.Command("schtasks.exe", "/Run", "/TN", trayTaskName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks run: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// stageTaskXML writes the task definition to a uniquely named file created with
// O_EXCL and returns its path. The caller owns removal.
func stageTaskXML(taskXML string) (string, error) {
	tempFile, err := os.CreateTemp("", "hooshix-tray-task-*.xml")
	if err != nil {
		return "", err
	}
	path := tempFile.Name()
	if err := writeUTF16LETo(tempFile, taskXML); err != nil {
		tempFile.Close()
		os.Remove(path)
		return "", err
	}
	if err := tempFile.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

// writeUTF16LETo encodes value as UTF-16LE with a BOM into an already opened
// file (the caller owns creation, permissions, and removal).
func writeUTF16LETo(file *os.File, value string) error {
	encoded := utf16.Encode([]rune(value))
	var data bytes.Buffer
	if err := binary.Write(&data, binary.LittleEndian, uint16(0xfeff)); err != nil {
		return err
	}
	if err := binary.Write(&data, binary.LittleEndian, encoded); err != nil {
		return err
	}
	if _, err := file.Write(data.Bytes()); err != nil {
		return err
	}
	return file.Sync()
}

func installPairingCapability(user string) error {
	stateDir, err := serviceStateDir()
	if err != nil {
		return err
	}
	// An empty user means no interactive desktop user could be resolved
	// (headless/unattended host). The interactive-user ACE is then simply
	// omitted: SYSTEM and Administrators remain, which is strictly narrower
	// than granting a principal that does not exist.
	userSID := ""
	if strings.TrimSpace(user) != "" {
		sid, _, _, err := windows.LookupSID("", user)
		if err != nil {
			return fmt.Errorf("resolve interactive user SID: %w", err)
		}
		userSID = "*" + sid.String()
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	// Recovery, not just repair: an earlier installation may have left files
	// with a SYSTEM-only DACL (service-created state), where even an elevated
	// administrator holds no WRITE_DAC, so icacls /grant alone fails with
	// "Access is denied". Recapture ownership first (an elevated admin always
	// holds SeTakeOwnershipPrivilege), then /reset replaces every explicit
	// DACL with inheritable ones so the grants below can never fail.
	if _, statErr := os.Stat(stateDir); statErr == nil {
		if err := recaptureStateOwnership(stateDir, userSID); err != nil {
			return fmt.Errorf("recover Agent state directory ownership: %w", err)
		}
	}
	// The directory DACL must exist BEFORE anything is written into it. Go mode
	// bits do not set a DACL on Windows, so a file created into a directory
	// that still inherits C:\ProgramData's ACEs stays readable by every local
	// user until a later per-file icacls runs — and the (OI)(CI) interactive
	// user grant would keep propagating that read access to every file added
	// afterwards. Hardening first means the capability is only ever created
	// inside an already-restricted directory.
	if err := hardenStateDirACL(stateDir, userSID); err != nil {
		return err
	}
	capability, err := agent.GeneratePairingCapability()
	if err != nil {
		return err
	}
	if err := agent.WritePairingCapability(stateDir, capability); err != nil {
		return err
	}
	path := agent.PairingCapabilityPath(stateDir)
	if err := hardenCapabilityACL(path, userSID); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// serviceStateDir resolves the machine-wide Agent state directory through the
// OS known-folder API rather than %ProgramData%: an environment variable that
// selects a recursive-delete target is attacker-influenced input, while
// FOLDERID_ProgramData is the operating system's own answer. The leaf is the
// fixed install-time name the service, the Agent and both uninstallers share.
func serviceStateDir() (string, error) {
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", fmt.Errorf("resolve the ProgramData known folder: %w", err)
	}
	return filepath.Join(root, stateDirName), nil
}

// hardenStateDirACL replaces the state directory's inherited DACL with explicit
// grants for SYSTEM, Administrators and (when one was resolved) the interactive
// desktop user only.
func hardenStateDirACL(stateDir, userSID string) error {
	args := []string{stateDir, "/inheritance:r"}
	args = appendUserGrant(args, userSID, "(OI)(CI)(RX)")
	args = append(args,
		"/grant:r", "*S-1-5-18:(OI)(CI)(F)",
		"/grant:r", "*S-1-5-32-544:(OI)(CI)(F)",
		"/T", "/Q")
	output, err := exec.Command("icacls.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("secure Agent state directory ACL: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// hardenCapabilityACL drops the inherited ACEs from the pairing capability
// itself so it is readable by exactly the intended principals.
func hardenCapabilityACL(path, userSID string) error {
	args := []string{path, "/inheritance:r"}
	args = appendUserGrant(args, userSID, "(R)")
	args = append(args,
		"/grant:r", "*S-1-5-18:(F)",
		"/grant:r", "*S-1-5-32-544:(F)")
	output, err := exec.Command("icacls.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("secure pairing capability ACL: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// appendUserGrant adds the interactive user's grant, or nothing when no
// interactive desktop user was resolved.
func appendUserGrant(args []string, userSID, rights string) []string {
	if strings.TrimSpace(userSID) == "" {
		return args
	}
	return append(args, "/grant:r", userSID+":"+rights)
}

func xmlEscape(value string) string {
	var escaped strings.Builder
	_ = xml.EscapeText(&escaped, []byte(value))
	return escaped.String()
}

// recaptureStateOwnership recovers the Agent state tree from legacy
// SYSTEM-only or otherwise inaccessible DACLs left by earlier builds. Even an
// elevated administrator holds no WRITE_DAC on such files, so icacls /grant
// and /reset both fail with "Access is denied"; transferring ownership first
// (always possible for an elevated admin via SeTakeOwnershipPrivilege) makes
// every subsequent repair succeed.
//
// Owner and DACL must be set in the SAME SetNamedSecurityInfo call: setting
// only the owner installs an empty (deny-all) DACL on the object and locks
// out the service. The replacement DACL grants SYSTEM and Administrators
// full control plus the interactive user read/execute, matching the grants
// the repair step below would otherwise apply through inheritance.
// Requires the elevated installer token; the privileges are enabled here so
// no locale-dependent takeown prompt is involved.
func recaptureStateOwnership(root, userSID string) error {
	// Build and validate the recovery descriptor FIRST: a malformed user SID or
	// SDDL must be rejected before any privilege is enabled or any object is
	// touched.
	sd, err := windows.SecurityDescriptorFromString(recoverySDDL(userSID))
	if err != nil {
		return fmt.Errorf("build recovery security descriptor: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("extract recovery owner: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("extract recovery DACL: %w", err)
	}
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("open process token: %w", err)
	}
	defer token.Close()
	if !token.IsElevated() {
		return errors.New("state ownership recovery requires the elevated installer token")
	}
	for _, privilege := range []string{"SeTakeOwnershipPrivilege", "SeRestorePrivilege"} {
		if err := enableTokenPrivilege(token, privilege); err != nil {
			return fmt.Errorf("enable %s: %w", privilege, err)
		}
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
			owner, nil, dacl, nil); err != nil {
			return fmt.Errorf("recover ownership and ACL of %s: %w", path, err)
		}
		return nil
	})
}

// recoverySDDL is the owner+DACL applied to every entry of the state tree by
// recaptureStateOwnership. O:BA owner = BUILTIN\Administrators; DACL: SYSTEM
// and Administrators full control (inherited) plus, when an interactive
// desktop user was resolved, that user's read+execute (inherited). The user ACE
// is omitted entirely for a headless/unattended host, which leaves a strictly
// narrower DACL than granting a principal that does not exist.
func recoverySDDL(userSID string) string {
	sddl := "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	if sid := strings.TrimPrefix(strings.TrimSpace(userSID), "*"); sid != "" {
		sddl += "(A;OICI;GRGX;;;" + sid + ")"
	}
	return sddl
}

func enableTokenPrivilege(token windows.Token, name string) error {
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	return windows.AdjustTokenPrivileges(token, false, &tp, uint32(unsafe.Sizeof(tp)), nil, nil)
}

func registerUninstall() error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, arpKeyPath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()
	values := map[string]string{
		"DisplayName": appTitle, "DisplayVersion": setupVersion, "Publisher": "HooshiX",
		"UninstallString": fmt.Sprintf(`"%s" --uninstall`, filepath.Join(installDir, uninstallBinary)),
		"InstallLocation": installDir, "DisplayIcon": filepath.Join(installDir, trayBinary),
	}
	for name, value := range values {
		if err := key.SetStringValue(name, value); err != nil {
			return err
		}
	}
	if err := key.SetDWordValue("NoModify", 1); err != nil {
		return err
	}
	return key.SetDWordValue("NoRepair", 1)
}

func pause() {
	if stdinInfo, err := os.Stdin.Stat(); err == nil && stdinInfo.Mode()&os.ModeCharDevice != 0 {
		fmt.Print("\nPress Enter to exit ...")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
}
