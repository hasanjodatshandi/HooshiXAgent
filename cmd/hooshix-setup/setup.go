//go:build windows

// HooshiX Agent Setup: installs the agent binaries, registers the Windows
// service, and launches the tray. Requires elevation (requests it via the
// standard UAC manifest directive compiled into the binary).
//
// Layout created:
//
//	C:\Program Files\HooshiXAgent\hooshix-agent.exe
//	C:\Program Files\HooshiXAgent\hooshix-agent-tray.exe
//	C:\ProgramData\HooshiXAgent\           (service state: config.json, status.json, token.txt)
//
// ARP entry: "HooshiX Agent" in Add/Remove Programs, uninstall = stop
// service, delete service, delete files.
package main

import (
	"bufio"
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/registry"
)

//go:embed payload/hooshix-agent.exe payload/hooshix-agent-tray.exe
var payload embed.FS

const (
	installDir  = `C:\Program Files\HooshiXAgent`
	arpKeyPath  = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HooshiXAgent`
	appTitle    = "HooshiX Agent"
	agentBinary = "hooshix-agent.exe"
	trayBinary  = "hooshix-agent-tray.exe"
)

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

	// Stop any previous installation first: the running service and tray
	// hold locks on the binaries we are about to replace.
	stopPreviousInstallation()

	if err := extractPayload(); err != nil {
		return fmt.Errorf("extract binaries: %w", err)
	}

	if err := registerUninstall(); err != nil {
		return fmt.Errorf("register uninstall entry: %w", err)
	}

	fmt.Println("installing service ...")
	if err := runAgentCommand("service", "install"); err != nil {
		return fmt.Errorf("install service: %w", err)
	}
	if err := runAgentCommand("service", "start"); err != nil {
		return fmt.Errorf("start service: %w", err)
	}

	fmt.Println("starting tray ...")
	_ = startTray()

	fmt.Println("done.")
	fmt.Println("The HooshiX Agent service is running.")
	fmt.Println("Use the tray icon (Open pairing page) to pair your device.")
	return nil
}

func extractPayload() error {
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return err
	}
	for _, name := range []string{agentBinary, trayBinary} {
		data, err := payload.ReadFile("payload/" + name)
		if err != nil {
			return err
		}
		target := filepath.Join(installDir, name)
		if writeErr := os.WriteFile(target, data, 0o755); writeErr != nil {
			return writeErr
		}
		fmt.Println("installed", target)
	}
	return nil
}

func runAgentCommand(args ...string) error {
	agentExe := filepath.Join(installDir, agentBinary)
	command := exec.Command(agentExe, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %w: %s", args, err, string(output))
	}
	if len(output) > 0 {
		fmt.Print(string(output))
	}
	return nil
}

// stopPreviousInstallation stops the running service and kills any leftover
// tray processes so binary files are writable again.
func stopPreviousInstallation() {
	_ = runAgentCommand("service", "stop")
	killProcessByName(trayBinary)
	killProcessByName(agentBinary)
	// Give the OS a moment to release file handles after process exit.
	time.Sleep(2 * time.Second)
}

func killProcessByName(name string) {
	taskkill := exec.Command("taskkill", "/F", "/IM", name)
	_ = taskkill.Run()
}

func registerUninstall() error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, arpKeyPath, registry.ALL_ACCESS)
	if err != nil {
		key, _, err = registry.CreateKey(registry.LOCAL_MACHINE, arpKeyPath, registry.ALL_ACCESS)
		if err != nil {
			return err
		}
	}
	defer key.Close()

	uninstallCmd := fmt.Sprintf(`"%s" --uninstall`, filepath.Join(installDir, agentBinary))
	strings := map[string]string{
		"DisplayName":     appTitle,
		"DisplayVersion":  "1.0.0",
		"Publisher":       "HooshiX",
		"UninstallString": uninstallCmd,
		"InstallLocation": installDir,
	}
	for name, value := range strings {
		if err := key.SetStringValue(name, value); err != nil {
			return err
		}
	}
	if err := key.SetDWordValue("NoModify", 1); err != nil {
		return err
	}
	return key.SetDWordValue("NoRepair", 1)
}

func startTray() error {
	trayExe := filepath.Join(installDir, trayBinary)
	command := exec.Command(trayExe)
	return command.Start()
}

func pause() {
	fmt.Print("\nPress Enter to exit ...")
	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
	_ = time.Second
}
