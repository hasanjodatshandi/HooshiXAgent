package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

const configVersion = 1

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

type Endpoint struct {
	ID     string `json:"id"`
	Target string `json:"target"`
}

type Config struct {
	Version         int        `json:"version"`
	GatewayURL      string     `json:"gateway_url,omitempty"`
	CAFile          string     `json:"ca_file,omitempty"`
	DeviceID        string     `json:"device_id,omitempty"`
	AuthorizationID string     `json:"authorization_id,omitempty"`
	TokenID         string     `json:"token_id,omitempty"`
	UpdateChannel   string     `json:"update_channel"`
	Endpoints       []Endpoint `json:"endpoints,omitempty"`
}

func DefaultConfig() Config {
	return Config{Version: configVersion, UpdateChannel: "stable"}
}

func DefaultStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	switch runtime.GOOS {
	case "windows":
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			return filepath.Join(local, "HooshiXAgent"), nil
		}
		return filepath.Join(home, "AppData", "Local", "HooshiXAgent"), nil
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "HooshiXAgent"), nil
	default:
		if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
			return filepath.Join(xdg, "hooshixagent"), nil
		}
		return filepath.Join(home, ".local", "state", "hooshixagent"), nil
	}
}

func ConfigPath(stateDir string) string {
	return filepath.Join(stateDir, "config.json")
}

func LoadConfig(stateDir string) (Config, error) {
	path := ConfigPath(stateDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DefaultConfig(), nil
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if config.Version != configVersion {
		return Config{}, fmt.Errorf("unsupported config version: %d", config.Version)
	}
	if config.UpdateChannel == "" {
		config.UpdateChannel = "stable"
	}
	return config, nil
}

func SaveConfig(stateDir string, config Config) error {
	config.Version = configVersion
	if config.UpdateChannel == "" {
		config.UpdateChannel = "stable"
	}
	sort.Slice(config.Endpoints, func(i, j int) bool { return config.Endpoints[i].ID < config.Endpoints[j].ID })
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')
	return writePrivateFile(stateDir, ConfigPath(stateDir), data)
}

func (config Config) ValidateRuntime() error {
	if config.Version != configVersion {
		return fmt.Errorf("unsupported config version: %d", config.Version)
	}
	if err := ValidateGatewayURL(config.GatewayURL); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"device_id":        config.DeviceID,
		"authorization_id": config.AuthorizationID,
		"token_id":         config.TokenID,
	} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%s is not a valid contract identifier", name)
		}
	}
	seen := make(map[string]struct{}, len(config.Endpoints))
	for _, endpoint := range config.Endpoints {
		if !identifierPattern.MatchString(endpoint.ID) {
			return fmt.Errorf("endpoint id %q is invalid", endpoint.ID)
		}
		if _, exists := seen[endpoint.ID]; exists {
			return fmt.Errorf("duplicate endpoint id %q", endpoint.ID)
		}
		seen[endpoint.ID] = struct{}{}
		if err := ValidateLocalTarget(endpoint.Target); err != nil {
			return fmt.Errorf("endpoint %s: %w", endpoint.ID, err)
		}
	}
	if config.UpdateChannel != "stable" && config.UpdateChannel != "beta" {
		return fmt.Errorf("unsupported update channel %q", config.UpdateChannel)
	}
	return nil
}

func ValidateGatewayURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse gateway URL: %w", err)
	}
	if parsed.Scheme != "wss" {
		return errors.New("gateway URL must use wss://")
	}
	if parsed.Host == "" || parsed.User != nil {
		return errors.New("gateway URL must contain a host and no userinfo")
	}
	if parsed.Path != "/agent/v1/connect" {
		return errors.New("gateway URL path must be /agent/v1/connect")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("gateway URL must not contain query or fragment")
	}
	return nil
}

func (config Config) EndpointByID(id string) (Endpoint, bool) {
	for _, endpoint := range config.Endpoints {
		if endpoint.ID == id {
			return endpoint, true
		}
	}
	return Endpoint{}, false
}

func (config *Config) SetEndpoint(endpoint Endpoint) {
	for index := range config.Endpoints {
		if config.Endpoints[index].ID == endpoint.ID {
			config.Endpoints[index] = endpoint
			return
		}
	}
	config.Endpoints = append(config.Endpoints, endpoint)
}

func (config *Config) RemoveEndpoint(id string) bool {
	for index := range config.Endpoints {
		if config.Endpoints[index].ID == id {
			config.Endpoints = append(config.Endpoints[:index], config.Endpoints[index+1:]...)
			return true
		}
	}
	return false
}

func NormalizeStateDir(stateDir string) (string, error) {
	if strings.TrimSpace(stateDir) == "" {
		return DefaultStateDir()
	}
	absolute, err := filepath.Abs(stateDir)
	if err != nil {
		return "", fmt.Errorf("resolve state directory: %w", err)
	}
	return absolute, nil
}
