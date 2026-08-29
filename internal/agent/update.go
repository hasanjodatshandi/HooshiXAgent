package agent

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"runtime/debug"
	"strings"
)

var Version = "dev"

type UpdateInfo struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Channel string `json:"channel"`
}

type UpdateCandidate struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

func CurrentUpdateInfo(channel string) UpdateInfo {
	version := Version
	if version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
	}
	if channel == "" {
		channel = "stable"
	}
	return UpdateInfo{Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH, Channel: channel}
}

func ValidateUpdateCandidate(candidate UpdateCandidate, current UpdateInfo) error {
	if strings.TrimSpace(candidate.Version) == "" {
		return errors.New("update version is required")
	}
	if candidate.OS != current.OS || candidate.Arch != current.Arch {
		return fmt.Errorf("update platform mismatch: candidate=%s/%s current=%s/%s", candidate.OS, candidate.Arch, current.OS, current.Arch)
	}
	parsed, err := url.Parse(candidate.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return errors.New("update URL must be an absolute HTTPS URL without userinfo")
	}
	digest, err := hex.DecodeString(candidate.SHA256)
	if err != nil || len(digest) != 32 || strings.ToLower(candidate.SHA256) != candidate.SHA256 {
		return errors.New("update SHA-256 must be 64 lowercase hexadecimal characters")
	}
	return nil
}
