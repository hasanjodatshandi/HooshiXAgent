package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hasanjodatshandi/HooshiXAgent/internal/connector"
)

// validBundle is the exact string hooshix-panel's buildConnectorBundle produces
// for grant-UPG9c9GFPY3Z, so the CLI is tested against the real Panel output.
const validBundle = "hx1.eyJ2IjoxLCJnYXRld2F5Ijoid3NzOi8vZWRnZS5ob29zaGl4LWFnZW50LmlyL2Nvbm5lY3Rvci92MS9jb25uZWN0IiwiZ3JhbnRfaWQiOiJncmFudC1VUEc5YzlHRlBZM1oiLCJ0b2tlbl9pZCI6InRva2VuLUM2X2o0OEI5IiwidG9rZW4iOiJBYkNkRWZHaDAxMjM0NTY3ODlhYmNkZWZnaGlqa2xtLV8iLCJwcm90b2NvbCI6InRjcCIsIm1heF9jb25uZWN0aW9ucyI6NH0"

func TestConfigFromFlagsBundle(t *testing.T) {
	config, err := configFromFlags([]string{"-bundle", validBundle})
	if err != nil {
		t.Fatalf("bundle config: %v", err)
	}
	if config.GatewayURL != "wss://edge.hooshix-agent.ir/connector/v1/connect" ||
		config.GrantID != "grant-UPG9c9GFPY3Z" ||
		config.TokenID != "token-C6_j48B9" ||
		config.Token == "" {
		t.Fatalf("bundle values missing: %+v", config)
	}
	if config.ListenAddress != "127.0.0.1:13389" || config.Protocol != "tcp" || config.MaxConnections != 4 {
		t.Fatalf("defaults/bundle overlay wrong: %+v", config)
	}
}

func TestConfigFromFlagsBundleKeepsItsOwnValuesAgainstFlagDefaults(t *testing.T) {
	config, err := configFromFlags([]string{"-bundle", validBundle, "-listen", "127.0.0.1:23389"})
	if err != nil {
		t.Fatalf("bundle with explicit listen: %v", err)
	}
	if config.ListenAddress != "127.0.0.1:23389" {
		t.Fatalf("-listen not applied: %+v", config)
	}
	// The bundle says 4; the unset -max-connections default must not erase it.
	if config.MaxConnections != 4 || config.Protocol != "tcp" {
		t.Fatalf("flag default clobbered the bundle: %+v", config)
	}
}

func TestConfigFromFlagsBundleRejectsIndividualConnectionFlags(t *testing.T) {
	for _, args := range [][]string{
		{"-bundle", validBundle, "-gateway", "wss://edge.hooshix-agent.ir/connector/v1/connect"},
		{"-bundle", validBundle, "-grant-id", "grant-other"},
		{"-bundle", validBundle, "-token-id", "token-other"},
		{"-bundle", validBundle, "-token-file", "token.txt"},
	} {
		if _, err := configFromFlags(args); !errors.Is(err, connector.ErrBundleExclusive) {
			t.Fatalf("%v: got %v, want ErrBundleExclusive", args, err)
		}
	}
}

func TestConfigFromFlagsBundleReportsBadInput(t *testing.T) {
	if _, err := configFromFlags([]string{"-bundle", "hx9.nope"}); err == nil {
		t.Fatal("unknown bundle version accepted")
	}
}

func TestConfigFromFlagsManualTokenFilePath(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.txt")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("a", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := configFromFlags([]string{
		"-gateway", "wss://edge.hooshix-agent.ir/connector/v1/connect",
		"-grant-id", "grant-UPG9c9GFPY3Z",
		"-token-id", "token-C6_j48B9",
		"-token-file", tokenPath,
	})
	if err != nil {
		t.Fatalf("manual path: %v", err)
	}
	if config.Token != strings.Repeat("a", 32) {
		t.Fatalf("token not trimmed from file: %q", config.Token)
	}
}

func TestConfigFromFlagsManualPathPointsAtBundle(t *testing.T) {
	_, err := configFromFlags(nil)
	if err == nil || !strings.Contains(err.Error(), "-bundle") {
		t.Fatalf("missing token file error must mention -bundle: %v", err)
	}
}
