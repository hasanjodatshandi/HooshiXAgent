package main

import (
	"fmt"
	"os"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/agent"
	agentsvc "github.com/hasanjodatshandi/HooshiXAgent/internal/agent/svc"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "service" {
		os.Exit(serviceMain(args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(agent.Main(args, os.Stdin, os.Stdout, os.Stderr))
}

// serviceMain implements the Windows integration commands. It lives here (not
// in package agent) to keep the agent dependency graph acyclic.
func serviceMain(args []string, stdin *os.File, stdout, stderr *os.File) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: hooshix-agent service <install|uninstall|start|stop|status|run-service|pairing-ui> [options]")
		return 2
	}
	sub, rest := args[0], args[1:]
	var err error
	switch sub {
	case "install":
		binary := flagValue(rest, "-binary")
		if binary == "" {
			if executable, execErr := os.Executable(); execErr == nil {
				binary = executable
			}
		}
		err = agentsvc.Install(binary)
	case "uninstall":
		err = agentsvc.Uninstall()
	case "start":
		err = agentsvc.Start()
	case "stop":
		err = agentsvc.Stop()
	case "status":
		var state string
		if state, err = agentsvc.QueryStatus(); err == nil {
			fmt.Fprintf(stdout, "service status: %s\n", state)
		}
	case "run-service":
		err = agentsvc.RunService(flagValue(rest, "-state-dir"))
	case "pairing-ui":
		err = agentsvc.PairingUI(flagValue(rest, "-state-dir"), stdout, stderr)
	default:
		err = fmt.Errorf("unknown service subcommand: %s", sub)
	}
	if err != nil {
		fmt.Fprintln(stderr, "agent:", err)
		return 1
	}
	return 0
}

// flagValue extracts "-flag value" from a flat argument list (minimal parsing
// for the service subcommands that only take path-style options).
func flagValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}
