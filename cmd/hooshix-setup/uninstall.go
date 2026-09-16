//go:build windows

package main

import (
	"bufio"
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

func runUninstall() error {
	if len(os.Args) < 2 || os.Args[1] != "--uninstall-worker" {
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
		cmd := exec.Command(worker, "--uninstall-worker", self)
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
	// The service may have left SYSTEM-only DACLs on ProgramData files, so
	// ownership is recaptured first where the state tree still exists.
	fmt.Println("removing agent state (ProgramData) ...")
	record("remove service state", removeAllState(stateDataDir()))
	fmt.Println("removing agent state (per-user) ...")
	if dir := userStateDir(); dir != "" {
		record("remove user state", os.RemoveAll(dir))
	}

	if len(failures) != 0 {
		return fmt.Errorf("uninstall incomplete: %s", strings.Join(failures, "; "))
	}
	fmt.Println("HooshiX Agent has been removed from this computer.")
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

// uninstallInvoked reports whether this run should perform an uninstall
// rather than an install (explicit flag or the interactive menu choice).
func uninstallInvoked() bool {
	if len(os.Args) > 1 && (os.Args[1] == "--uninstall" || os.Args[1] == "--uninstall-worker") {
		return true
	}
	return false
}

// promptUninstall asks the user at the console whether to uninstall. Only the
// interactive (console) path can reach this; stdin redirection skips the
// prompt and returns false so scripted runs keep installing.
func promptUninstall() bool {
	if stdinInfo, err := os.Stdin.Stat(); err != nil || stdinInfo.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	fmt.Println("  1) install / repair the HooshiX Agent (default)")
	fmt.Println("  2) uninstall the HooshiX Agent (removes service, tray, and state)")
	fmt.Print("choose an option [1]: ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	return line == "2" || strings.EqualFold(line, "uninstall")
}

func init() {
	if len(os.Args) > 1 && (os.Args[1] == "--uninstall" || os.Args[1] == "--uninstall-worker") {
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
