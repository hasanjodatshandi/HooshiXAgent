package connector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const (
	dataFrame      byte = 0
	halfCloseFrame byte = 1
	maxPayload          = 1 << 20
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

type Config struct {
	GatewayURL     string
	Protocol       string
	GrantID        string
	TokenID        string
	Token          string
	ListenAddress  string
	MaxConnections int
	DialTimeout    time.Duration
	IdleTimeout    time.Duration
	WriteTimeout   time.Duration
	HTTPClient     *http.Client
}

func DefaultConfig() Config {
	return Config{
		Protocol: "tcp", ListenAddress: "127.0.0.1:13389", MaxConnections: 4,
		DialTimeout: 10 * time.Second, IdleTimeout: 5 * time.Minute, WriteTimeout: 15 * time.Second,
	}
}

func (config Config) Validate() error {
	if config.Protocol != "tcp" && config.Protocol != "udp" {
		return errors.New("connector protocol must be tcp or udp")
	}
	parsed, err := url.Parse(config.GatewayURL)
	if err != nil || parsed.Scheme != "wss" || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != "/connector/v1/connect" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("gateway URL must be wss://<host>/connector/v1/connect without credentials, query, or fragment")
	}
	if !idPattern.MatchString(config.GrantID) || !idPattern.MatchString(config.TokenID) {
		return errors.New("grant ID and token ID must be valid contract identifiers")
	}
	if len(config.Token) < 32 || len(config.Token) > 512 || strings.ContainsAny(config.Token, " \t\r\n") {
		return errors.New("connector token must be 32..512 non-whitespace characters")
	}
	if err := validateLoopbackAddress(config.ListenAddress); err != nil {
		return err
	}
	if config.MaxConnections < 1 || config.MaxConnections > 16 {
		return errors.New("max connections must be in 1..16")
	}
	if config.DialTimeout <= 0 || config.IdleTimeout <= 0 || config.WriteTimeout <= 0 {
		return errors.New("connector timeouts must be positive")
	}
	return nil
}

func Run(ctx context.Context, config Config, logger *slog.Logger) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if config.Protocol == "udp" {
		listener, err := net.ListenPacket("udp", config.ListenAddress)
		if err != nil {
			return fmt.Errorf("listen on private UDP connector loopback: %w", err)
		}
		return ServeUDP(ctx, listener, config, logger)
	}
	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen on private connector loopback: %w", err)
	}
	return Serve(ctx, listener, config, logger)
}

func Serve(ctx context.Context, listener net.Listener, config Config, logger *slog.Logger) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if listener == nil || !listenerIsLoopback(listener) {
		return errors.New("connector listener must be bound to loopback")
	}
	if logger == nil {
		logger = slog.Default()
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	slots := make(chan struct{}, config.MaxConnections)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept connector client: %w", err)
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				defer conn.Close()
				if err := proxy(ctx, conn, config); err != nil && ctx.Err() == nil {
					logger.Warn("connector flow ended", "error", err)
				}
			}()
		default:
			_ = conn.Close()
		}
	}
}

func proxy(parent context.Context, local net.Conn, config Config) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	headers := http.Header{
		"Authorization":      []string{"Bearer " + config.Token},
		"X-Hooshix-Grant-ID": []string{config.GrantID},
		"X-Hooshix-Token-ID": []string{config.TokenID},
	}
	dialCtx, dialCancel := context.WithTimeout(ctx, config.DialTimeout)
	remote, response, err := websocket.Dial(dialCtx, config.GatewayURL, &websocket.DialOptions{
		HTTPHeader: headers, HTTPClient: config.HTTPClient, CompressionMode: websocket.CompressionDisabled,
	})
	dialCancel()
	if err != nil {
		if response != nil {
			return fmt.Errorf("connector gateway rejected connection: HTTP %d", response.StatusCode)
		}
		return fmt.Errorf("dial connector gateway: %w", err)
	}
	defer remote.CloseNow()
	remote.SetReadLimit(maxPayload + 1)

	toRemote := make(chan error, 1)
	go func() { toRemote <- copyToGateway(ctx, remote, local, config.WriteTimeout) }()
	fromRemote := copyFromGateway(ctx, remote, local, config)
	if fromRemote != nil {
		cancel()
		_ = local.Close()
	}
	toRemoteErr := <-toRemote
	_ = remote.Close(websocket.StatusNormalClosure, "connector flow complete")
	if fromRemote != nil {
		return fromRemote
	}
	return toRemoteErr
}

func copyToGateway(ctx context.Context, remote *websocket.Conn, local net.Conn, writeTimeout time.Duration) error {
	buffer := make([]byte, 32<<10)
	for {
		n, err := local.Read(buffer)
		if n > 0 {
			payload := make([]byte, n+1)
			payload[0] = dataFrame
			copy(payload[1:], buffer[:n])
			writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
			writeErr := remote.Write(writeCtx, websocket.MessageBinary, payload)
			cancel()
			if writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return err
			}
			writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
			writeErr := remote.Write(writeCtx, websocket.MessageBinary, []byte{halfCloseFrame})
			cancel()
			return writeErr
		}
	}
}

func copyFromGateway(ctx context.Context, remote *websocket.Conn, local net.Conn, config Config) error {
	for {
		readCtx, cancel := context.WithTimeout(ctx, config.IdleTimeout)
		messageType, payload, err := remote.Read(readCtx)
		cancel()
		if err != nil {
			return err
		}
		if messageType != websocket.MessageBinary || len(payload) == 0 {
			return errors.New("invalid gateway connector frame")
		}
		switch payload[0] {
		case dataFrame:
			if err := writeAll(local, payload[1:], config.WriteTimeout); err != nil {
				return err
			}
		case halfCloseFrame:
			if len(payload) != 1 {
				return errors.New("invalid gateway half-close frame")
			}
			if tcp, ok := local.(interface{ CloseWrite() error }); ok {
				return tcp.CloseWrite()
			}
			return errors.New("local connector socket does not support half-close")
		default:
			return errors.New("unknown gateway connector frame")
		}
	}
}

func writeAll(conn net.Conn, payload []byte, timeout time.Duration) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

func validateLoopbackAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return errors.New("listen address must be an explicit loopback host:port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("connector listener must use a loopback IP literal")
	}
	return nil
}

func listenerIsLoopback(listener net.Listener) bool {
	address, ok := listener.Addr().(*net.TCPAddr)
	return ok && address.IP.IsLoopback()
}
