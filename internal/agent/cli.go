package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

var sessionTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,512}$`)

// SessionTokenPattern is the exported session-token grammar shared with the
// local pairing UI.
var SessionTokenPattern = sessionTokenPattern

func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	var err error
	switch args[0] {
	case "init":
		err = commandInit(args[1:], stdout)
	case "configure":
		err = commandConfigure(args[1:], stdin, stdout)
	case "rotate":
		err = commandRotate(args[1:], stdin, stdout)
	case "unpair":
		err = commandUnpair(args[1:], stdout)
	case "expose":
		err = commandExpose(args[1:], stdout)
	case "status":
		err = commandStatus(args[1:], stdout)
	case "doctor":
		err = commandDoctor(args[1:], stdout)
	case "run":
		err = commandRun(args[1:], stderr)
	case "service-spec":
		err = commandServiceSpec(args[1:], stdout)
	case "update-info":
		err = commandUpdateInfo(args[1:], stdout)
	case "version":
		info := CurrentUpdateInfo("stable")
		fmt.Fprintf(stdout, "%s %s/%s\n", info.Version, info.OS, info.Arch)
		return 0
	default:
		printUsage(stderr)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "agent:", err)
		return 1
	}
	return 0
}

func commandInit(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDir := flags.String("state-dir", "", "Agent state directory")
	jsonOutput := flags.Bool("json", false, "JSON output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	dir, err := NormalizeStateDir(*stateDir)
	if err != nil {
		return err
	}
	store := NewPlatformSecretStore(dir)
	publicKey, err := initializeAgentState(dir, store, stateMutationFaults{})
	if err != nil {
		return err
	}
	result := map[string]any{"state_dir": dir, "public_key": PublicKeyBase64(publicKey), "secret_store": store.Kind()}
	return printResult(stdout, *jsonOutput, result, "initialized state=%s public_key=%s secret_store=%s\n", dir, PublicKeyBase64(publicKey), store.Kind())
}

func commandConfigure(args []string, stdin io.Reader, stdout io.Writer) error {
	flags := flag.NewFlagSet("configure", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDir := flags.String("state-dir", "", "Agent state directory")
	gatewayURL := flags.String("gateway", "", "Gateway WSS URL")
	gatewayAliases := flags.String("gateway-alias", "", "comma-separated failover Gateway WSS URLs (optional)")
	caFile := flags.String("ca-file", "", "optional trusted CA PEM file")
	deviceID := flags.String("device-id", "", "externally assigned device ID")
	authorizationID := flags.String("authorization-id", "", "external authorization ID")
	tokenID := flags.String("token-id", "", "external token ID")
	tokenStdin := flags.Bool("token-stdin", false, "read session token from stdin")
	channel := flags.String("update-channel", "stable", "stable or beta")
	jsonOutput := flags.Bool("json", false, "JSON output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*tokenStdin {
		return errors.New("--token-stdin is required so session tokens are not placed in process arguments")
	}
	if err := ValidateGatewayURL(*gatewayURL); err != nil {
		return err
	}
	var aliases []string
	if raw := strings.TrimSpace(*gatewayAliases); raw != "" {
		for _, alias := range strings.Split(raw, ",") {
			alias = strings.TrimSpace(alias)
			if alias == "" {
				continue
			}
			aliases = append(aliases, alias)
		}
	}
	if len(aliases) > MaxGatewayAliases {
		return fmt.Errorf("at most %d gateway aliases are supported", MaxGatewayAliases)
	}
	for name, value := range map[string]string{"device-id": *deviceID, "authorization-id": *authorizationID, "token-id": *tokenID} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	if *channel != "stable" && *channel != "beta" {
		return errors.New("update channel must be stable or beta")
	}
	token, err := readSecretLine(stdin)
	if err != nil {
		return err
	}
	if !sessionTokenPattern.MatchString(token) {
		return errors.New("session token must be 32..512 base64url-safe characters")
	}
	dir, err := NormalizeStateDir(*stateDir)
	if err != nil {
		return err
	}
	store := NewPlatformSecretStore(dir)
	config, err := configureAgentState(dir, store, Config{
		GatewayURL:      *gatewayURL,
		GatewayAliases:  aliases,
		CAFile:          *caFile,
		DeviceID:        *deviceID,
		AuthorizationID: *authorizationID,
		TokenID:         *tokenID,
		UpdateChannel:   *channel,
	}, token, stateMutationFaults{})
	if err != nil {
		return err
	}
	return printResult(stdout, *jsonOutput, map[string]any{"configured": true, "device_id": config.DeviceID, "gateways": config.GatewayCandidates()}, "configured device=%s gateways=%d\n", config.DeviceID, len(config.GatewayCandidates()))
}

// commandRotate replaces the device Ed25519 identity under the ADR-0002
// key-locality boundary. The new seed is generated on-device inside the
// transactional secret store; the private key never leaves the machine.
// Rotation is operator-confirmed because existing sessions continue on the
// old key only until their natural expiry, and the external Control Panel
// must register the emitted public key before re-authentication can succeed.
func commandRotate(args []string, stdin io.Reader, stdout io.Writer) error {
	flags := flag.NewFlagSet("rotate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDir := flags.String("state-dir", "", "Agent state directory")
	force := flags.Bool("force", false, "rotate without interactive confirmation")
	jsonOutput := flags.Bool("json", false, "JSON output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*force {
		fmt.Fprintln(stdout, "Rotation replaces this device identity; the new public key must be registered externally before reconnect. Continue? [y/N]")
		confirmed, err := readConfirmLine(stdin)
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("rotation aborted")
		}
	}
	dir, err := NormalizeStateDir(*stateDir)
	if err != nil {
		return err
	}
	store := NewPlatformSecretStore(dir)
	publicKey, err := rotateAgentIdentity(dir, store, stateMutationFaults{})
	if err != nil {
		return err
	}
	result := map[string]any{"rotated": true, "public_key": PublicKeyBase64(publicKey), "secret_store": store.Kind()}
	return printResult(stdout, *jsonOutput, result, "rotated public_key=%s secret_store=%s\n", PublicKeyBase64(publicKey), store.Kind())
}

func readConfirmLine(reader io.Reader) (bool, error) {
	limited := io.LimitReader(reader, 64)
	line, err := bufio.NewReader(limited).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// commandUnpair clears the pairing and returns the Agent to the unpaired
// (pending_config) state. It is a single operation: when the machine-wide
// service owns the state the command coordinates with the running service
// (which is the only process that can rewrite a LocalSystem DPAPI secret
// store), and otherwise it applies the same atomic state transaction itself.
func commandUnpair(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("unpair", flag.ContinueOnError)
	flags.SetOutput(stdout)
	stateDir := flags.String("state-dir", "", "Agent state directory")
	resetIdentity := flags.Bool("reset-identity", false, "ALSO replace the device Ed25519 identity (a NEW public key must be registered in the panel before re-pairing); without it the existing identity is kept so the same device can be re-paired as itself")
	jsonOutput := flags.Bool("json", false, "JSON output")
	flags.Usage = func() { printUnpairUsage(stdout, flags) }
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	dir, err := NormalizeStateDir(*stateDir)
	if err != nil {
		return err
	}
	result, err := unpairState(dir, *resetIdentity)
	if err != nil {
		return err
	}
	return printUnpairResult(stdout, *jsonOutput, result)
}

func printUnpairUsage(stdout io.Writer, flags *flag.FlagSet) {
	fmt.Fprintln(stdout, "usage: hooshix-agent unpair [--state-dir <dir>] [--reset-identity] [--json]")
	fmt.Fprintln(stdout, "Clears the pairing record (gateway URL/aliases, trust anchor, device/authorization/token IDs)")
	fmt.Fprintln(stdout, "and the session token, returning the agent to the unpaired \"waiting for pairing\" state.")
	fmt.Fprintln(stdout, "Local endpoint mappings are preserved: they are local exposure configuration, not pairing material.")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "  default (no flags)   KEEPS this device's Ed25519 identity: re-pairing the same device reuses the")
	fmt.Fprintln(stdout, "                       public key the panel already authorized.")
	fmt.Fprintln(stdout, "--reset-identity       REPLACES the identity with a new one. Use only when a genuinely new device")
	fmt.Fprintln(stdout, "                       identity is wanted; the new public key must be registered in the panel.")
	fmt.Fprintln(stdout, "                       The replacement key is created by the process that owns the secret store")
	fmt.Fprintln(stdout, "                       (the Agent service on Windows), never by an unrelated account.")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Running it on an already-unpaired agent succeeds and reports that there was nothing to clear.")
	flags.PrintDefaults()
}

func printUnpairResult(stdout io.Writer, asJSON bool, result UnpairResult) error {
	identity := "device identity preserved"
	if !result.IdentityPreserved {
		identity = "device identity REPLACED"
	}
	key := result.PublicKey
	if key == "" {
		key = "none"
	}
	var summary string
	switch {
	case result.AlreadyUnpaired:
		summary = fmt.Sprintf("already unpaired: no pairing record or session token to clear state_dir=%s %s public_key=%s endpoints_preserved=%d\n",
			result.StateDir, identity, key, result.LocalEndpoints)
	case result.IdentityPreserved:
		summary = fmt.Sprintf("unpaired: cleared pairing and session token state_dir=%s device=%s %s public_key=%s endpoints_preserved=%d\nregister this device again from the panel to reconnect\n",
			result.StateDir, result.DeviceID, identity, key, result.LocalEndpoints)
	default:
		summary = fmt.Sprintf("unpaired: cleared pairing, session token, and the previous identity state_dir=%s device=%s %s public_key=%s endpoints_preserved=%d\nregister the NEW public key in the panel before re-pairing\n",
			result.StateDir, result.DeviceID, identity, key, result.LocalEndpoints)
	}
	if asJSON {
		return printResult(stdout, true, result, "%s", summary)
	}
	_, err := io.WriteString(stdout, summary)
	return err
}
func commandExpose(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("expose requires add, remove, or list")
	}
	switch args[0] {
	case "add":
		flags := flag.NewFlagSet("expose add", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		stateDir := flags.String("state-dir", "", "Agent state directory")
		id := flags.String("id", "", "local endpoint ID")
		target := flags.String("target", "", "loopback host:port")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if !identifierPattern.MatchString(*id) {
			return errors.New("endpoint ID is invalid")
		}
		if err := ValidateLocalTarget(*target); err != nil {
			return err
		}
		dir, err := NormalizeStateDir(*stateDir)
		if err != nil {
			return err
		}
		if err := MutateConfig(dir, func(config *Config) error {
			config.SetEndpoint(Endpoint{ID: *id, Target: *target})
			return nil
		}); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "exposed %s -> %s\n", *id, *target)
		return nil
	case "remove":
		flags := flag.NewFlagSet("expose remove", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		stateDir := flags.String("state-dir", "", "Agent state directory")
		id := flags.String("id", "", "local endpoint ID")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		dir, err := NormalizeStateDir(*stateDir)
		if err != nil {
			return err
		}
		if err := MutateConfig(dir, func(config *Config) error {
			if !config.RemoveEndpoint(*id) {
				return errors.New("endpoint not found")
			}
			return nil
		}); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "removed %s\n", *id)
		return nil
	case "list":
		flags := flag.NewFlagSet("expose list", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		stateDir := flags.String("state-dir", "", "Agent state directory")
		jsonOutput := flags.Bool("json", false, "JSON output")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		dir, err := NormalizeStateDir(*stateDir)
		if err != nil {
			return err
		}
		config, err := LoadConfig(dir)
		if err != nil {
			return err
		}
		if *jsonOutput {
			return json.NewEncoder(stdout).Encode(config.Endpoints)
		}
		for _, endpoint := range config.Endpoints {
			fmt.Fprintf(stdout, "%s\t%s\n", endpoint.ID, endpoint.Target)
		}
		return nil
	default:
		return errors.New("expose requires add, remove, or list")
	}
}

func commandStatus(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDir := flags.String("state-dir", "", "Agent state directory")
	jsonOutput := flags.Bool("json", false, "JSON output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	dir, err := NormalizeStateDir(*stateDir)
	if err != nil {
		return err
	}
	config, err := LoadConfig(dir)
	if err != nil {
		return err
	}
	store := NewPlatformSecretStore(dir)
	publicKey, _, err := LoadIdentity(store)
	if err != nil {
		return err
	}
	state, err := store.Load()
	if err != nil {
		return err
	}
	result := map[string]any{
		"state_dir":           dir,
		"device_id":           config.DeviceID,
		"public_key":          PublicKeyBase64(publicKey),
		"gateway_url":         config.GatewayURL,
		"gateway_candidates":  config.GatewayCandidates(),
		"endpoint_count":      len(config.Endpoints),
		"credentials_present": state.SessionToken != "",
		"secret_store":        store.Kind(),
		"update_channel":      config.UpdateChannel,
	}
	return printResult(stdout, *jsonOutput, result, "state_dir=%s device=%s public_key=%s gateway=%s gateways=%d endpoints=%d credentials=%t secret_store=%s\n", dir, config.DeviceID, PublicKeyBase64(publicKey), config.GatewayURL, len(config.GatewayCandidates()), len(config.Endpoints), state.SessionToken != "", store.Kind())
}

func commandDoctor(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDir := flags.String("state-dir", "", "Agent state directory")
	dialLocal := flags.Bool("dial-local", false, "test local endpoint connectivity")
	if err := flags.Parse(args); err != nil {
		return err
	}
	dir, err := NormalizeStateDir(*stateDir)
	if err != nil {
		return err
	}
	config, err := LoadConfig(dir)
	if err != nil {
		return err
	}
	if err := config.ValidateRuntime(); err != nil {
		return err
	}
	store := NewPlatformSecretStore(dir)
	if _, _, err := LoadIdentity(store); err != nil {
		return err
	}
	if _, err := LoadSessionToken(store); err != nil {
		return err
	}
	if _, err := tlsConfigForAgent(config); err != nil {
		return err
	}
	if *dialLocal {
		for _, endpoint := range config.Endpoints {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			conn, err := DialLocalTarget(ctx, endpoint.Target, time.Second)
			cancel()
			if err != nil {
				return fmt.Errorf("endpoint %s connectivity: %w", endpoint.ID, err)
			}
			conn.Close()
		}
	}
	fmt.Fprintf(stdout, "doctor: PASSED state_dir=%s device=%s endpoints=%d secret_store=%s\n", dir, config.DeviceID, len(config.Endpoints), store.Kind())
	return nil
}

func commandRun(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDir := flags.String("state-dir", "", "Agent state directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	dir, err := NormalizeStateDir(*stateDir)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	runner, err := NewRunner(dir, DefaultLimits(), logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runner.Run(ctx)
}

func commandServiceSpec(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("service-spec", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDir := flags.String("state-dir", "", "Agent state directory")
	binary := flags.String("binary", "", "Agent executable path")
	jsonOutput := flags.Bool("json", false, "JSON output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	dir, err := NormalizeStateDir(*stateDir)
	if err != nil {
		return err
	}
	bin := *binary
	if bin == "" {
		bin, err = os.Executable()
		if err != nil {
			return err
		}
	}
	spec, err := NativeServiceSpec(runtime.GOOS, bin, dir)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(stdout).Encode(spec)
	}
	_, err = io.WriteString(stdout, spec.Native)
	return err
}

func commandUpdateInfo(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("update-info", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDir := flags.String("state-dir", "", "Agent state directory")
	jsonOutput := flags.Bool("json", false, "JSON output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	dir, err := NormalizeStateDir(*stateDir)
	if err != nil {
		return err
	}
	config, err := LoadConfig(dir)
	if err != nil {
		return err
	}
	info := CurrentUpdateInfo(config.UpdateChannel)
	return printResult(stdout, *jsonOutput, info, "version=%s platform=%s/%s channel=%s\n", info.Version, info.OS, info.Arch, info.Channel)
}

func readSecretLine(reader io.Reader) (string, error) {
	limited := io.LimitReader(reader, 514)
	line, err := bufio.NewReader(limited).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read session token: %w", err)
	}
	line = strings.TrimSpace(line)
	if len(line) > 512 {
		return "", errors.New("session token is too long")
	}
	return line, nil
}

func printResult(writer io.Writer, asJSON bool, value any, format string, args ...any) error {
	if asJSON {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(value)
	}
	_, err := fmt.Fprintf(writer, format, args...)
	return err
}

func printUsage(writer io.Writer) {
	commands := []struct{ name, description string }{
		{"init", "initialize the state directory and the device identity"},
		{"configure", "apply externally issued pairing credentials (token on stdin)"},
		{"rotate", "replace the device Ed25519 identity, keeping the session token"},
		{"unpair", "clear the pairing and session token; keeps the device identity unless --reset-identity"},
		{"expose add|remove|list", "manage approved local loopback mappings"},
		{"status", "show the current state summary"},
		{"doctor", "validate the local configuration, identity and credentials"},
		{"run", "run the long-lived tunnel client"},
		{"service-spec", "print the native service definition for this platform"},
		{"update-info", "print version/platform/channel information"},
		{"version", "print the agent version"},
	}
	sort.Slice(commands, func(i, j int) bool { return commands[i].name < commands[j].name })
	fmt.Fprintln(writer, "usage: hooshix-agent <command> [options]")
	fmt.Fprintln(writer, "commands:")
	for _, command := range commands {
		fmt.Fprintf(writer, "  %-24s %s\n", command.name, command.description)
	}
	fmt.Fprintln(writer, "run `hooshix-agent <command> --help` for one command's options")
}
