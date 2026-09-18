//go:build windows

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
)

// userStateDirs returns the per-user agent state directories that must be
// cleared on uninstall, for the INTERACTIVE desktop user.
//
// The uninstaller runs elevated, so its own %LOCALAPPDATA% (and the worker
// process's) belongs to the ELEVATED account, not the person whose tray wrote
// logs there (contrast interactiveUser(), which resolves the console session
// user via WTS). The resolved user's profile is looked up through their SID so
// the correct directory is targeted; the elevated account's own directory is
// included only when it differs and actually exists, so nothing is left behind
// on an elevated-then-uninstalled machine.
func userStateDirs() []string {
	var dirs []string
	seen := map[string]bool{}
	add := func(localAppData string) {
		if localAppData == "" {
			return
		}
		dir := filepath.Join(localAppData, "HooshiXAgent")
		if seen[dir] {
			return
		}
		seen[dir] = true
		dirs = append(dirs, dir)
	}
	if user, err := interactiveUser(); err == nil {
		if sid, _, _, sidErr := windows.LookupSID("", user); sidErr == nil {
			if dir := profileLocalAppData(sid); dir != "" {
				add(dir)
			}
		} else {
			fmt.Fprintln(os.Stderr, "uninstall: resolving the desktop user's profile:", sidErr)
		}
	} else {
		fmt.Fprintln(os.Stderr, "uninstall: no interactive user resolved:", err)
	}
	// The elevated account's own directory comes from the OS known-folder API,
	// not %LOCALAPPDATA%: an environment variable must never select a
	// recursive-delete target.
	if localAppData, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT); err == nil {
		add(localAppData)
	} else {
		fmt.Fprintln(os.Stderr, "uninstall: resolving the elevated account's LocalAppData:", err)
	}
	return dirs
}

// profileLocalAppData returns <profile>\AppData\Local for a user SID, from the
// ProfileList registry key (the same mapping Windows itself uses).
func profileLocalAppData(sid *windows.SID) string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+sid.String(), registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	profile, _, err := key.GetStringValue("ProfileImagePath")
	if err != nil || strings.TrimSpace(profile) == "" {
		return ""
	}
	return filepath.Join(profile, "AppData", "Local")
}

// uninstallOptions carries the user's cleanup choices into the worker.
type uninstallOptions struct {
	KeepConfig bool
}

// keepConfigFlag is passed to the worker process (argument lists cannot hold
// bools) so the interactive choice survives the parent→worker handoff. The
// scripted --uninstall path defaults to full cleanup unless this flag is set.
const keepConfigFlag = "--keep-config"

// The Agent's own versioned state-ownership marker (internal/agent/files.go).
// It is repeated here because it is the contract between an uninstaller and
// the state tree it is allowed to destroy, not an implementation detail.
const (
	stateMarkerName    = ".hooshix-agent-state"
	stateMarkerVersion = "hooshix-agent-state-v1"
)

func runUninstall() error {
	keepConfig := false
	for _, arg := range os.Args[1:] {
		if arg == keepConfigFlag {
			keepConfig = true
		}
	}
	if len(os.Args) < 2 || (os.Args[1] != "--uninstall-worker" && os.Args[1] != keepConfigFlag) {
		// The parent copies itself to %TEMP% so the installer EXE can be
		// deleted from the install directory while it is still running. The
		// worker self-deletes after uninstall so no scheduled task or stale
		// executable remains behind.
		self, err := os.Executable()
		if err != nil {
			return err
		}
		worker := filepath.Join(os.TempDir(), fmt.Sprintf("hooshix-uninstall-%d.exe", time.Now().UnixNano()))
		data, err := os.ReadFile(self)
		if err != nil {
			return err
		}
		if err := os.WriteFile(worker, data, 0o755); err != nil {
			return err
		}
		args := []string{"--uninstall-worker", self}
		if keepConfig {
			args = append(args, keepConfigFlag)
		}
		cmd := exec.Command(worker, args...)
		if err := cmd.Start(); err != nil {
			_ = os.Remove(worker)
			return err
		}
		return nil
	}

	var failures []string
	record := func(label string, err error) {
		if err != nil {
			failures = append(failures, label+": "+err.Error())
			fmt.Fprintln(os.Stderr, "uninstall:", label+":", err)
		} else {
			fmt.Println("  ok:", label)
		}
	}
	// Stop/end operations are idempotent best-effort: Windows reports errors
	// when an object is already stopped, which is a valid uninstall state.
	fmt.Println("stopping the HooshiX Agent service ...")
	installedAgent := filepath.Join(installDir, agentBinary)
	if _, statErr := os.Stat(installedAgent); statErr != nil {
		// Without the binary the service cannot be removed through it. That is
		// not a success: an SCM registration can outlive its image, and the
		// operator has to know rather than discover it at the next boot.
		record("remove service", fmt.Errorf("the installed %s is missing, so the service could not be removed; check `sc.exe query %s`", agentBinary, agent.WindowsServiceName))
	} else {
		_ = runAgentCommand("service", "stop")
		record("remove service", runAgentCommand("service", "uninstall"))
	}

	fmt.Println("removing the tray and its auto-start task ...")
	_ = runCommand("schtasks.exe", "/End", "/TN", trayTaskName)
	_ = runCommand("schtasks.exe", "/Delete", "/F", "/TN", trayTaskName)
	killProcessByName(trayBinary)
	// Verify rather than assume: a task that survived deletion would relaunch
	// the tray against a removed installation on the next logon.
	if err := runCommand("schtasks.exe", "/Query", "/TN", trayTaskName); err != nil {
		record("remove tray task", nil)
	} else {
		record("remove tray task", errors.New("the tray task is still registered"))
	}

	fmt.Println("removing the Windows uninstall entry ...")
	// A machine where the entry was never written (or was already removed by an
	// earlier run) is a valid uninstall state, not a failure.
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, arpKeyPath); err != nil && !errors.Is(err, registry.ErrNotExist) {
		record("remove ARP entry", err)
	} else {
		record("remove ARP entry", nil)
	}

	fmt.Println("removing program files ...")
	for deadline := time.Now().Add(10 * time.Second); ; {
		err := os.RemoveAll(installDir)
		if err == nil || time.Now().After(deadline) {
			record("remove install directory", err)
			break
		}
		time.Sleep(250 * time.Millisecond)
	}

	// State cleanup runs last and is best-effort: leftover credentials in
	// ProgramData are machine-scoped secrets (DPAPI under LocalSystem) and
	// the LOCALAPPDATA copy holds per-user logs; both must go on uninstall.
	// KeepConfig preserves the pairing/configuration files so a reinstall
	// reconnects without re-pairing, while credentials stay local. The
	// service may have left SYSTEM-only DACLs on ProgramData files, so
	// ownership is recaptured first where the state tree still exists.
	if serviceState, err := stateDataDir(); err != nil {
		record("resolve service state", err)
	} else if keepConfig {
		fmt.Println("keeping configuration (keep-config selected) ...")
		record("preserve configuration", preserveStateConfig(serviceState))
	} else {
		fmt.Println("removing agent state (ProgramData) ...")
		record("remove service state", removeAllState(serviceState))
	}
	fmt.Println("removing agent state (per-user) ...")
	for _, dir := range userStateDirs() {
		if _, err := os.Lstat(dir); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			record("inspect user state "+dir, err)
			continue
		}
		fmt.Println("  user state:", dir)
		// A per-user directory is only removed when the Agent's marker proves
		// it created the tree; a misdirected path must never be a recursive
		// delete target.
		if err := guardOwnedStateDir(dir); err != nil {
			record("remove user state", err)
			continue
		}
		record("remove user state", os.RemoveAll(dir))
	}

	if len(failures) != 0 {
		return fmt.Errorf("uninstall incomplete: %s", strings.Join(failures, "; "))
	}
	if keepConfig {
		fmt.Println("HooshiX Agent has been removed. Configuration was kept and will be reused by the next install.")
	} else {
		fmt.Println("HooshiX Agent has been removed from this computer.")
	}
	return nil
}

// preserveStateConfig repairs ownership of the state tree (see
// removeAllState) and then removes everything except the pairing/config
// records: config.json, the secret store, and the state marker stay so the
// next install reconnects without re-pairing. Logs, status, and the
// capability file are dropped (they are regenerated on install).
func preserveStateConfig(root string) error {
	if err := guardOwnedStateDir(root); err != nil {
		return err
	}
	if _, err := os.Lstat(root); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := recaptureStateOwnership(root, ""); err != nil {
		fmt.Fprintln(os.Stderr, "uninstall: state ownership recovery skipped:", err)
	}
	keep := map[string]bool{
		"config.json":          true,
		"secrets.dpapi":        true,
		"secrets.json":         true,
		".hooshix-agent-state": true,
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	var failures []string
	for _, entry := range entries {
		if keep[entry.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			failures = append(failures, entry.Name())
		}
	}
	if len(failures) != 0 {
		return errors.New("could not remove: " + strings.Join(failures, ", "))
	}
	return nil
}

// stateDataDir returns the machine-wide service state directory from the
// OS known-folder API. This uninstaller runs elevated and recursively deletes
// whatever this function returns, so the path must not be derivable from the
// environment: %ProgramData% is process-environment input an attacker with a
// foothold can set, while FOLDERID_ProgramData is the operating system's own
// answer. The leaf is the same fixed install-time name the installer and the
// Agent's ServiceStateDir() use.
func stateDataDir() (string, error) {
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", fmt.Errorf("resolve the ProgramData known folder: %w", err)
	}
	return filepath.Join(root, stateDirName), nil
}

// guardOwnedStateDir applies the ownership-marker rule every packaged
// uninstaller already enforces (packaging/agent/README.md, R-9): a non-empty
// directory may only be recursively removed when it carries the Agent's valid
// versioned marker. It runs BEFORE ownership recapture or any delete, because
// both follow paths and would otherwise act on the target of a reparse point.
func guardOwnedStateDir(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refusing to remove a non-directory or reparse-point state path: %s", root)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	marker := filepath.Join(root, stateMarkerName)
	markerInfo, err := os.Lstat(marker)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("refusing to remove unowned non-empty state directory without a %s marker: %s", stateMarkerName, root)
		}
		return err
	}
	if markerInfo.Mode()&os.ModeSymlink != 0 || markerInfo.IsDir() {
		return fmt.Errorf("refusing to remove state directory whose %s marker is not a regular file: %s", stateMarkerName, root)
	}
	contents, err := os.ReadFile(marker)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(contents)) != stateMarkerVersion {
		return fmt.Errorf("refusing to remove state directory with an invalid %s marker: %s", stateMarkerName, root)
	}
	return nil
}

// removeAllState deletes the agent state tree, first repairing legacy
// SYSTEM-only DACLs (service-created state) that deny even an elevated
// administrator WRITE_DAC. Ownership recovery makes os.RemoveAll succeed;
// without it the directory is left half-deleted on upgraded installs.
func removeAllState(root string) error {
	if err := guardOwnedStateDir(root); err != nil {
		return err
	}
	if _, err := os.Lstat(root); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := recaptureStateOwnership(root, ""); err != nil {
		fmt.Fprintln(os.Stderr, "uninstall: state ownership recovery skipped:", err)
	}
	return os.RemoveAll(root)
}

func runCommand(name string, args ...string) error {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func scheduleSelfDelete(path string) {
	// cmd.exe waits briefly for this process to release its image, then removes
	// the exact random worker path. The generated path contains no shell
	// metacharacters; strip quotes defensively before interpolation.
	path = strings.ReplaceAll(path, `"`, "")
	command := `ping 127.0.0.1 -n 3 > nul & del /f /q "` + path + `"`
	_ = exec.Command("cmd.exe", "/D", "/C", command).Start()
}

// promptUninstall asks the user at the console what to do, and whether an
// uninstall should keep the configuration (so the next install reconnects
// without re-pairing). Only the interactive (console) path can reach this;
// stdin redirection skips the prompt and returns false so scripted runs
// keep installing.
func promptUninstall() (uninstall, keepConfig bool) {
	if stdinInfo, err := os.Stdin.Stat(); err != nil || stdinInfo.Mode()&os.ModeCharDevice == 0 {
		return false, false
	}
	fmt.Println("  1) install / repair the HooshiX Agent (default)")
	fmt.Println("  2) uninstall and remove everything (service, tray, config, credentials)")
	fmt.Println("  3) uninstall but keep the configuration (next install reconnects without re-pairing)")
	fmt.Print("choose an option [1]: ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	switch {
	case line == "2" || strings.EqualFold(line, "uninstall"):
		return true, false
	case line == "3" || strings.EqualFold(line, "keep"):
		return true, true
	default:
		return false, false
	}
}

func init() {
	if len(os.Args) > 1 && (os.Args[1] == "--uninstall" || os.Args[1] == "--uninstall-worker" || os.Args[1] == keepConfigFlag) {
		err := runUninstall()
		if os.Args[1] == "--uninstall-worker" {
			if self, selfErr := os.Executable(); selfErr == nil {
				scheduleSelfDelete(self)
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			pause()
			os.Exit(1)
		}
		pause()
		os.Exit(0)
	}
}
