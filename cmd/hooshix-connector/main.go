package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/connector"
)

// bundleFlags are the connection inputs a bundle already carries, so passing
// them together with -bundle is a contradiction rather than a merge.
var bundleFlags = []string{"gateway", "grant-id", "token-id", "token-file"}

func main() {
	config, err := configFromFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "connector:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := connector.Run(ctx, config, slog.Default()); err != nil {
		fmt.Fprintln(os.Stderr, "connector:", err)
		os.Exit(1)
	}
}

// configFromFlags builds a connector config from command-line arguments. A
// -bundle supplies the gateway, grant, token ID and token in one pasted string;
// the individual flags and -token-file remain for the manual path. -listen,
// -protocol, -max-connections and -ca-file always override, bundle or not —
// -ca-file because a bundle carries no trust information at all.
func configFromFlags(args []string) (connector.Config, error) {
	config := connector.DefaultConfig()
	set := flag.NewFlagSet("hooshix-connector", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	tokenFile := set.String("token-file", "", "path to the one-time Connector token file")
	bundle := set.String("bundle", "", "hx1. connect bundle from the Panel (replaces -gateway, -grant-id, -token-id and -token-file)")
	gateway := set.String("gateway", "", "wss:// gateway connector URL")
	grantID := set.String("grant-id", "", "scoped Connector grant ID")
	tokenID := set.String("token-id", "", "Connector token ID")
	listen := set.String("listen", config.ListenAddress, "local loopback listener")
	protocol := set.String("protocol", config.Protocol, "tcp or udp")
	maxConnections := set.Int("max-connections", config.MaxConnections, "bounded local concurrent connections (1..16)")
	caFile := set.String("ca-file", "", "PEM trust anchor for a privately-CA'd Gateway (never part of a bundle)")
	if err := set.Parse(args); err != nil {
		return connector.Config{}, err
	}
	present := map[string]bool{}
	set.Visit(func(f *flag.Flag) { present[f.Name] = true })

	if strings.TrimSpace(*bundle) != "" {
		for _, name := range bundleFlags {
			if present[name] {
				return connector.Config{}, connector.ErrBundleExclusive
			}
		}
		parsed, err := connector.ParseBundle(*bundle)
		if err != nil {
			return connector.Config{}, err
		}
		config = parsed.Config(config)
	} else {
		config.GatewayURL = *gateway
		config.GrantID = *grantID
		config.TokenID = *tokenID
		token, err := readToken(*tokenFile)
		if err != nil {
			return connector.Config{}, err
		}
		config.Token = token
	}
	// These always override, but only when the operator actually passed them:
	// applying a flag default here would erase the bundle's own values.
	if present["listen"] {
		config.ListenAddress = *listen
	}
	if present["protocol"] {
		config.Protocol = *protocol
	}
	if present["max-connections"] {
		config.MaxConnections = *maxConnections
	}
	if present["ca-file"] {
		config.CAFile = *caFile
	}
	if err := config.Validate(); err != nil {
		return connector.Config{}, err
	}
	return config, nil
}

func readToken(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("-token-file is required (or pass -bundle)")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open token file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 513 {
		return "", errors.New("token file must be a regular file no larger than 513 bytes")
	}
	payload, err := io.ReadAll(io.LimitReader(file, 514))
	if err != nil {
		return "", fmt.Errorf("read token file: %w", err)
	}
	return strings.TrimSpace(string(payload)), nil
}
