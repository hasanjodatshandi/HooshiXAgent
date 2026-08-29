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
	config, err := LoadConfig(dir)
	if err != nil {
		return err
	}
	if err := SaveConfig(dir, config); err != nil {
		return err
	}
	store := NewPlatformSecretStore(dir)
	publicKey, _, err := LoadOrCreateIdentity(store)
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
	config, err := LoadConfig(dir)
	if err != nil {
		return err
	}
	config.GatewayURL = *gatewayURL
	config.CAFile = *caFile
	config.DeviceID = *deviceID
	config.AuthorizationID = *authorizationID
	config.TokenID = *tokenID
	config.UpdateChannel = *channel
	if err := config.ValidateRuntime(); err != nil {
		return err
	}
	if err := SaveConfig(dir, config); err != nil {
		return err
	}
	store := NewPlatformSecretStore(dir)
	if _, _, err := LoadOrCreateIdentity(store); err != nil {
		return err
	}
	if err := SetSessionToken(store, token); err != nil {
		return err
	}
	return printResult(stdout, *jsonOutput, map[string]any{"configured": true, "device_id": config.DeviceID}, "configured device=%s\n", config.DeviceID)
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
		config, err := LoadConfig(dir)
		if err != nil {
			return err
		}
		config.SetEndpoint(Endpoint{ID: *id, Target: *target})
		if err := SaveConfig(dir, config); err != nil {
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
		config, err := LoadConfig(dir)
		if err != nil {
			return err
		}
		if !config.RemoveEndpoint(*id) {
			return errors.New("endpoint not found")
		}
		if err := SaveConfig(dir, config); err != nil {
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
	publicKey, _, err := LoadOrCreateIdentity(store)
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
		"endpoint_count":      len(config.Endpoints),
		"credentials_present": state.SessionToken != "",
		"secret_store":        store.Kind(),
		"update_channel":      config.UpdateChannel,
	}
	return printResult(stdout, *jsonOutput, result, "device=%s public_key=%s gateway=%s endpoints=%d credentials=%t secret_store=%s\n", config.DeviceID, PublicKeyBase64(publicKey), config.GatewayURL, len(config.Endpoints), state.SessionToken != "", store.Kind())
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
	if _, _, err := LoadOrCreateIdentity(store); err != nil {
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
	fmt.Fprintf(stdout, "doctor: PASSED device=%s endpoints=%d secret_store=%s\n", config.DeviceID, len(config.Endpoints), store.Kind())
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
	commands := []string{"configure", "doctor", "expose add|remove|list", "init", "run", "service-spec", "status", "update-info", "version"}
	sort.Strings(commands)
	fmt.Fprintln(writer, "usage: hooshix-agent <command> [options]")
	fmt.Fprintln(writer, "commands:")
	for _, command := range commands {
		fmt.Fprintln(writer, "  "+command)
	}
}
