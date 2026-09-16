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

	"golang.org/x/sys/windows/registry"
)

// userStateDir returns the per-user agent state directory the tray and any
// non-service agent runs write to (LOCALAPPDATA\HooshiXAgent). Uninstall must
// clear it as well as the SYSTEM service state in ProgramData.
func userStateDir() string {
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		return filepath.Join(local, "HooshiXAgent")
	}
	return ""
}

// uninstallOptions carries the user's cleanup choices into the worker.
type uninstallOptions struct {
	KeepConfig bool
}

// keepConfigFlag is passed to the worker process (argument lists cannot hold
// bools) so the interactive choice survives the parent→worker handoff. The
// scripted --uninstall path defaults to full cleanup unless this flag is set.
const keepConfigFlag = "--keep-config"

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
	_ = runAgentCommand("service", "stop")
	record("remove service", runAgentCommand("service", "uninstall"))

	fmt.Println("removing the tray and its auto-start task ...")
	_ = runCommand("schtasks.exe", "/End", "/TN", trayTaskName)
	_ = runCommand("schtasks.exe", "/Delete", "/F", "/TN", trayTaskName)
	killProcessByName(trayBinary)

	fmt.Println("removing the Windows uninstall entry ...")
	record("remove ARP entry", registry.DeleteKey(registry.LOCAL_MACHINE, arpKeyPath))

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
	if keepConfig {
		fmt.Println("keeping configuration (keep-config selected) ...")
		record("preserve configuration", preserveStateConfig(stateDataDir()))
	} else {
		fmt.Println("removing agent state (ProgramData) ...")
		record("remove service state", removeAllState(stateDataDir()))
	}
	fmt.Println("removing agent state (per-user) ...")
	if dir := userStateDir(); dir != "" {
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

// stateDataDir mirrors svc.StateDir() without importing the agent package:
// the service state lives under ProgramData\HooshiXAgent on every supported
// Windows installation.
func stateDataDir() string {
	if programData := os.Getenv("ProgramData"); programData != "" {
		return filepath.Join(programData, "HooshiXAgent")
	}
	return `C:\ProgramData\HooshiXAgent`
}

// removeAllState deletes the agent state tree, first repairing legacy
// SYSTEM-only DACLs (service-created state) that deny even an elevated
// administrator WRITE_DAC. Ownership recovery makes os.RemoveAll succeed;
// without it the directory is left half-deleted on upgraded installs.
func removeAllState(root string) error {
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
