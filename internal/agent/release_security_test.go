package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"strings"
	"testing"
)

func TestReleaseLocalTargetPolicyAdversarialCases(t *testing.T) {
	t.Parallel()

	denied := []string{
		"127.0.0.1:0",
		"127.0.0.1:65536",
		"127.0.0.1:http",
		"127.0.0.1",
		"127.0.0.1:80/path",
		"localhost.:80",
		"example.invalid:80",
		"[fe80::1]:80",
		"[ff02::1]:80",
		"[2001:db8::1]:80",
		"169.254.169.254:80",
		"100.100.100.200:80",
		"metadata.google.internal:80",
		"http://127.0.0.1:80",
		"https://localhost:443",
		"file:///etc/passwd",
		`\\.\pipe\docker_engine`,
		"/var/run/docker.sock",
	}
	for _, target := range denied {
		target := target
		t.Run(target, func(t *testing.T) {
			if err := ValidateLocalTarget(target); err == nil {
				t.Fatalf("adversarial target %q was accepted", target)
			}
		})
	}
}

func TestReleaseUpdateCandidateFailsClosed(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256([]byte("release-artifact"))
	valid := UpdateCandidate{
		Version: "v9.9.9",
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		URL:     "https://downloads.example.invalid/hooshix-agent",
		SHA256:  hex.EncodeToString(digest[:]),
	}
	current := CurrentUpdateInfo("stable")
	if err := ValidateUpdateCandidate(valid, current); err != nil {
		t.Fatalf("valid release candidate rejected: %v", err)
	}

	cases := map[string]UpdateCandidate{
		"missing version":  func() UpdateCandidate { c := valid; c.Version = ""; return c }(),
		"wrong os":         func() UpdateCandidate { c := valid; c.OS = "not-" + current.OS; return c }(),
		"wrong arch":       func() UpdateCandidate { c := valid; c.Arch = "not-" + current.Arch; return c }(),
		"plaintext url":    func() UpdateCandidate { c := valid; c.URL = "http://downloads.example.invalid/agent"; return c }(),
		"relative url":     func() UpdateCandidate { c := valid; c.URL = "/agent"; return c }(),
		"userinfo url":     func() UpdateCandidate { c := valid; c.URL = "https://token@downloads.example.invalid/agent"; return c }(),
		"short digest":     func() UpdateCandidate { c := valid; c.SHA256 = strings.Repeat("0", 62); return c }(),
		"uppercase digest": func() UpdateCandidate { c := valid; c.SHA256 = strings.ToUpper(valid.SHA256); return c }(),
		"non hex digest":   func() UpdateCandidate { c := valid; c.SHA256 = strings.Repeat("z", 64); return c }(),
	}
	for name, candidate := range cases {
		name, candidate := name, candidate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateUpdateCandidate(candidate, current); err == nil {
				t.Fatalf("unsafe update candidate accepted: %#v", candidate)
			}
		})
	}
}
