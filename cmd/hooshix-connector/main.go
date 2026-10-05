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

func main() {
	config := connector.DefaultConfig()
	tokenFile := flag.String("token-file", "", "path to the one-time Connector token file")
	flag.StringVar(&config.GatewayURL, "gateway", "", "wss:// gateway connector URL")
	flag.StringVar(&config.GrantID, "grant-id", "", "scoped Connector grant ID")
	flag.StringVar(&config.TokenID, "token-id", "", "Connector token ID")
	flag.StringVar(&config.ListenAddress, "listen", config.ListenAddress, "local loopback listener")
	flag.StringVar(&config.Protocol, "protocol", config.Protocol, "tcp or udp")
	flag.IntVar(&config.MaxConnections, "max-connections", config.MaxConnections, "bounded local concurrent connections (1..16)")
	flag.Parse()

	token, err := readToken(*tokenFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connector:", err)
		os.Exit(2)
	}
	config.Token = token
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := connector.Run(ctx, config, slog.Default()); err != nil {
		fmt.Fprintln(os.Stderr, "connector:", err)
		os.Exit(1)
	}
}

func readToken(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("-token-file is required")
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
