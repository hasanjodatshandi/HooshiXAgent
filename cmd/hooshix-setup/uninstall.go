//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

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
		}
	}
	// Stop/end operations are idempotent best-effort: Windows reports errors
	// when an object is already stopped, which is a valid uninstall state.
	_ = runAgentCommand("service", "stop")
	record("remove service", runAgentCommand("service", "uninstall"))
	_ = runCommand("schtasks.exe", "/End", "/TN", trayTaskName)
	_ = runCommand("schtasks.exe", "/Delete", "/F", "/TN", trayTaskName)
	killProcessByName(trayBinary)
	record("remove ARP entry", registry.DeleteKey(registry.LOCAL_MACHINE, arpKeyPath))
	for deadline := time.Now().Add(10 * time.Second); ; {
		err := os.RemoveAll(installDir)
		if err == nil || time.Now().After(deadline) {
			record("remove install directory", err)
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if len(failures) != 0 {
		return fmt.Errorf("uninstall incomplete: %s", strings.Join(failures, "; "))
	}
	return nil
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
		os.Exit(0)
	}
}
