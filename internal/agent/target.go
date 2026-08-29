package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func ValidateLocalTarget(target string) error {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return errors.New("local target must be host:port with an explicit port")
	}
	if strings.ContainsAny(host, "/\\") || strings.Contains(target, "://") {
		return errors.New("local target schemes and paths are not allowed")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("local target port must be in 1..65535")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("local target host must be localhost, 127.0.0.0/8, or ::1")
	}
	return nil
}

func DialLocalTarget(ctx context.Context, target string, timeout time.Duration) (net.Conn, error) {
	if err := ValidateLocalTarget(target); err != nil {
		return nil, err
	}
	host, port, _ := net.SplitHostPort(target)
	dialer := net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	if !strings.EqualFold(host, "localhost") {
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}

	var lastErr error
	for _, loopback := range []string{"127.0.0.1", "::1"} {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(loopback, port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("dial localhost loopback candidates: %w", lastErr)
}
