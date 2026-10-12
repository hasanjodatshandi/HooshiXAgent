package agent

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// ConfigVersion is the supported Agent config schema version. Exported for
// callers that construct a Config for validation before persistence.
const ConfigVersion = 1

const configVersion = ConfigVersion

// MaxGatewayAliases bounds the HA failover list so configuration cannot grow
// an unbounded reconnect schedule.
const MaxGatewayAliases = 4

// MaxEndpoints bounds the local exposure list. It matches the session-level
// stream ceiling: a larger config cannot serve more concurrent streams than
// MaxStreams, so accepting more entries would only grow state and attack
// surface without adding capacity.
const MaxEndpoints = 64

// MaxCAFileSize bounds how much of a configured trust-anchor file is read
// while validating it. Any realistic PEM CA bundle is far below this; the
// bound exists so a path pointed at a huge or special file cannot turn
// validation into an unbounded read.
const MaxCAFileSize = 1 << 20

const (
	// settingsFileName is the operator-editable settings file name.
	settingsFileName = "config.json"
	// settingsLocationName is the pointer file inside the state directory that
	// redirects the settings file into the installation directory, so the file
	// an operator edits sits next to the program instead of under ProgramData.
	settingsLocationName = "settings_location"
	// maxSettingsFileBytes bounds every state-file read: the settings pointer,
	// the settings file it names, and the records kept beside them. They are all
	// a few kilobytes of JSON, so the bound keeps a mistyped or hostile file
	// from turning a config read into an unbounded one.
	maxSettingsFileBytes = 1 << 20
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

type Endpoint struct {
	ID       string `json:"id"`
	Target   string `json:"target"`
	Protocol string `json:"protocol,omitempty"`
}

type Config struct {
	Version         int           `json:"version"`
	GatewayURL      string        `json:"gateway_url,omitempty"`
	GatewayAliases  []string      `json:"gateway_aliases,omitempty"`
	CAFile          string        `json:"ca_file,omitempty"`
	DeviceID        string        `json:"device_id,omitempty"`
	AuthorizationID string        `json:"authorization_id,omitempty"`
	TokenID         string        `json:"token_id,omitempty"`
	UpdateChannel   string        `json:"update_channel"`
	Endpoints       []Endpoint    `json:"endpoints,omitempty"`
	Limits          *LimitsConfig `json:"limits,omitempty"`
}

// GatewayCandidates returns the validated, de-duplicated failover list:
// the primary GatewayURL first, then aliases. All candidates must use the
// exact approved WSS path. An empty result means no gateway is configured.
func (config Config) GatewayCandidates() []string {
	seen := make(map[string]struct{}, 1+len(config.GatewayAliases))
	candidates := make([]string, 0, 1+len(config.GatewayAliases))
	for _, raw := range append([]string{config.GatewayURL}, config.GatewayAliases...) {
		if raw == "" {
			continue
		}
		if _, exists := seen[raw]; exists {
			continue
		}
		seen[raw] = struct{}{}
		candidates = append(candidates, raw)
	}
	return candidates
}

func DefaultConfig() Config {
	return Config{Version: configVersion, UpdateChannel: "stable"}
}

// DefaultStateDir resolves the state directory a CLI invocation uses when
// --state-dir is omitted. On Windows it prefers the machine-wide service state
// directory whenever a service installation already owns state there: an
// operator following the CLI help on a machine with the service installed must
// operate on the SAME identity the service uses, not silently create a second
// identity under their user profile and register the wrong public key.
func DefaultStateDir() (string, error) {
	if runtime.GOOS == "windows" && serviceInstallationPresent() {
		return ServiceStateDir(), nil
	}
	return defaultLocalStateDir()
}

// defaultLocalStateDir is the per-user state directory, used when no service
// installation owns machine-wide state.
func defaultLocalStateDir() (string, error) {
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

// ConfigPath returns the settings file this Agent installation reads and
// writes. By default it is <stateDir>/config.json. Setup.exe can redirect it
// into the installation directory next to the binaries by writing a
// settings_location pointer inside the state directory; the pointer is the only
// way the location moves, so a portable or development run that never had one
// behaves exactly as before.
func ConfigPath(stateDir string) string {
	if target, ok := redirectedSettingsPath(stateDir); ok {
		return target
	}
	return filepath.Join(stateDir, settingsFileName)
}

// redirectedSettingsPath resolves and validates the settings_location pointer.
// Anything malformed, relative, escaping through a reparse point, or naming a
// file that is not config.json is ignored rather than obeyed: falling back to
// the state directory keeps the Agent running, while trusting a bad pointer
// would let one stray file move the Agent's configuration silently.
func redirectedSettingsPath(stateDir string) (string, bool) {
	data, err := readStateFile(filepath.Join(stateDir, settingsLocationName))
	if err != nil {
		return "", false
	}
	target := strings.TrimSpace(string(data))
	if target == "" || !filepath.IsAbs(target) || filepath.Base(target) != settingsFileName {
		return "", false
	}
	target = filepath.Clean(target)
	if samePath(filepath.Dir(target), filepath.Clean(stateDir)) {
		return "", false
	}
	if err := validateStateDirectoryPath(filepath.Dir(target), true); err != nil {
		return "", false
	}
	return target, true
}

// WriteSettingsLocation points this installation's settings file at path and
// persists the pointer. Setup.exe calls it during installation so the file an
// operator edits sits next to the program.
func WriteSettingsLocation(stateDir, path string) error {
	normalized, err := NormalizeStateDir(stateDir)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(path) || filepath.Base(path) != settingsFileName {
		return errors.New("settings location must be an absolute path ending in config.json")
	}
	path = filepath.Clean(path)
	if err := validateStateDirectoryPath(filepath.Dir(path), true); err != nil {
		return fmt.Errorf("validate settings directory: %w", err)
	}
	return withConfigLock(normalized, func() error {
		return writeStateFile(normalized, filepath.Join(normalized, settingsLocationName), []byte(path+"\n"))
	})
}

func LoadConfig(stateDir string) (Config, error) {
	normalized, err := NormalizeStateDir(stateDir)
	if err != nil {
		return Config{}, err
	}
	if err := ensureStateReadable(normalized); err != nil {
		return Config{}, err
	}
	return loadConfigUnlocked(normalized)
}

func loadConfigUnlocked(stateDir string) (Config, error) {
	path := ConfigPath(stateDir)
	data, err := readStateFile(path)
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
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("decode config: trailing JSON value")
		}
		return Config{}, fmt.Errorf("decode config trailing data: %w", err)
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
	normalized, err := NormalizeStateDir(stateDir)
	if err != nil {
		return err
	}
	return withConfigLock(normalized, func() error {
		return saveConfigUnlocked(normalized, config)
	})
}

func MutateConfig(stateDir string, mutate func(*Config) error) error {
	normalized, err := NormalizeStateDir(stateDir)
	if err != nil {
		return err
	}
	return withConfigLock(normalized, func() error {
		config, err := loadConfigUnlocked(normalized)
		if err != nil {
			return err
		}
		if err := mutate(&config); err != nil {
			return err
		}
		return saveConfigUnlocked(normalized, config)
	})
}

func saveConfigUnlocked(stateDir string, config Config) error {
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
	return writeStateFile(stateDir, ConfigPath(stateDir), data)
}

// writeStateFile writes data to destination using the rules that fit where it
// lives. Inside the state directory a file is private: it is created through the
// private temp/protect path, because that directory holds the Agent's secrets.
// Outside it the destination is the redirected operator-editable settings file
// in the installation directory: the file is still replaced atomically, but its
// access rights are deliberately left to the directory's own ACL. Tightening
// them would take the file away from the tray and the CLI, and loosening the
// directory would damage the installed binaries' permissions.
func writeStateFile(stateDir, destination string, data []byte) error {
	if samePath(filepath.Dir(destination), filepath.Clean(stateDir)) {
		return writePrivateFile(stateDir, destination, data)
	}
	return writeSettingsOutsideState(destination, data)
}

func writeSettingsOutsideState(path string, data []byte) error {
	if len(data) > maxSettingsFileBytes {
		return fmt.Errorf("settings file exceeds the %d byte limit", maxSettingsFileBytes)
	}
	directory := filepath.Dir(path)
	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("settings directory %s is unavailable: %w", filepath.Base(path), err)
	}
	if !info.IsDir() {
		return fmt.Errorf("settings directory %s is not a directory", filepath.Base(path))
	}
	// Advisory, not atomic: a symlink or directory placed here after this check
	// cannot be used to redirect the write, because rename replaces the
	// destination ENTRY rather than following it. The check exists to refuse a
	// link or directory that is already in the way, not to make this pair
	// indivisible.
	if existing, err := os.Lstat(path); err == nil {
		if existing.Mode()&os.ModeSymlink != 0 || !existing.Mode().IsRegular() {
			return errors.New("refusing to replace a non-regular settings file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect settings file: %w", err)
	}
	temp, err := os.CreateTemp(directory, ".tmp-hooshix-settings-*")
	if err != nil {
		return fmt.Errorf("create settings temp file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	// World-readable on purpose: the settings file is not a secret (identity
	// key material stays in the state directory) and both the LocalSystem
	// service and the signed-in user's tray/CLI must read the same file.
	if err := temp.Chmod(0o644); err != nil {
		temp.Close()
		return fmt.Errorf("chmod settings temp file: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("write settings file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync settings file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close settings temp file: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace settings file: %w", err)
	}
	// Flush the directory entry so the rename itself survives a crash, exactly
	// as writePrivateFile does for state files. On Windows syncDirectory is a
	// documented no-op (NTFS journals metadata) and the data was already
	// flushed by temp.Sync above.
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("sync settings directory: %w", err)
	}
	return nil
}

func (config Config) ValidateRuntime() error {
	if config.Version != configVersion {
		return fmt.Errorf("unsupported config version: %d", config.Version)
	}
	if err := ValidateGatewayURL(config.GatewayURL); err != nil {
		return err
	}
	if len(config.GatewayAliases) > MaxGatewayAliases {
		return fmt.Errorf("gateway_aliases exceed the bounded failover list size %d", MaxGatewayAliases)
	}
	seenAlias := make(map[string]struct{}, len(config.GatewayAliases))
	for _, alias := range config.GatewayAliases {
		if err := ValidateGatewayURL(alias); err != nil {
			return fmt.Errorf("gateway alias %q: %w", alias, err)
		}
		if _, duplicate := seenAlias[alias]; duplicate {
			return fmt.Errorf("duplicate gateway alias %q", alias)
		}
		if alias == config.GatewayURL {
			return fmt.Errorf("gateway alias %q duplicates the primary gateway URL", alias)
		}
		seenAlias[alias] = struct{}{}
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
	if len(config.Endpoints) > MaxEndpoints {
		return fmt.Errorf("endpoints exceed the bounded exposure list size %d", MaxEndpoints)
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
		if endpoint.Protocol != "" && endpoint.Protocol != "tcp" && endpoint.Protocol != "udp" {
			return fmt.Errorf("endpoint %s: unsupported protocol %q", endpoint.ID, endpoint.Protocol)
		}
	}
	if config.UpdateChannel != "stable" && config.UpdateChannel != "beta" {
		return fmt.Errorf("unsupported update channel %q", config.UpdateChannel)
	}
	return nil
}

// ValidateCAFile verifies that path names an existing, readable regular file
// whose contents include at least one PEM CERTIFICATE block that parses and
// installs into a real x509 trust pool.
//
// The check is deliberately about content, not about existence. The Agent
// reads this path at session time while running as LocalSystem, so accepting
// an unvalidated operator-supplied path would make the configured trust
// anchor an arbitrary file-read primitive for the service account. Merely
// parsing as PEM is not enough either: a PEM PRIVATE KEY block is valid PEM
// and is still not a trust anchor, so at least one parsed certificate is
// required. Whether that certificate is a CA is not required — pinning a
// self-signed server certificate is a supported self-hosted/test deployment.
func ValidateCAFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("CA file path is empty")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open CA file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect CA file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("CA file must be a regular file, not a directory or device")
	}
	if info.Size() == 0 {
		return errors.New("CA file is empty")
	}
	if info.Size() > MaxCAFileSize {
		return fmt.Errorf("CA file exceeds the %d byte trust-anchor limit", MaxCAFileSize)
	}
	pemData, err := io.ReadAll(io.LimitReader(file, MaxCAFileSize))
	if err != nil {
		return fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return errors.New("CA file contains no PEM certificate that loads as a trust anchor")
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
		defaultDir, err := DefaultStateDir()
		if err != nil {
			return "", err
		}
		stateDir = defaultDir
	}
	absolute, err := filepath.Abs(stateDir)
	if err != nil {
		return "", fmt.Errorf("resolve state directory: %w", err)
	}
	absolute = filepath.Clean(absolute)
	volumeRoot := filepath.Clean(filepath.VolumeName(absolute) + string(os.PathSeparator))
	if absolute == volumeRoot {
		return "", errors.New("state directory must not be a filesystem root")
	}
	if home, err := os.UserHomeDir(); err == nil {
		homeAbs, absErr := filepath.Abs(home)
		if absErr == nil && samePath(absolute, filepath.Clean(homeAbs)) {
			return "", errors.New("state directory must not be the user home directory")
		}
	}
	if err := validateStateDirectoryPath(absolute, true); err != nil {
		return "", fmt.Errorf("validate state directory path: %w", err)
	}
	return absolute, nil
}

func samePath(left, right string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}
