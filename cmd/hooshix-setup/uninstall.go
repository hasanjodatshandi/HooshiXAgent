//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// runUninstall is the "--uninstall" path invoked by Add/Remove Programs:
// stop and remove the service, remove the ARP entry, delete files. State
// (ProgramData) is preserved so re-install keeps pairing.
func runUninstall() error {
	fmt.Println("=== HooshiX Agent Uninstall ===")
	if err := runAgentCommand("service", "stop"); err != nil {
		fmt.Println("note:", err)
	}
	if err := runAgentCommand("service", "uninstall"); err != nil {
		fmt.Println("note:", err)
	}
	if err := removeUninstallEntry(); err != nil {
		fmt.Println("note: remove uninstall entry:", err)
	}
	if err := os.RemoveAll(installDir); err != nil {
		return fmt.Errorf("delete %s: %w", installDir, err)
	}
	fmt.Println("removed", installDir)
	fmt.Println("state kept in C:\\ProgramData\\HooshiXAgent (delete manually to reset pairing)")
	return nil
}

func removeUninstallEntry() error {
	return registry.DeleteKey(registry.LOCAL_MACHINE, arpKeyPath)
}

func init() {
	if len(os.Args) > 1 && os.Args[1] == "--uninstall" {
		if err := runUninstall(); err != nil {
			fmt.Fprintln(os.Stderr, "uninstall failed:", err)
			pause()
			os.Exit(1)
		}
		pause()
		os.Exit(0)
	}
	_ = filepath.Join
	_ = exec.Command
}
