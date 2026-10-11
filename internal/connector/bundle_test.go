package connector

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func testBundle(t *testing.T, mutate func(*Bundle)) string {
	t.Helper()
	bundle := Bundle{
		GatewayURL:     "wss://edge.hooshix-agent.ir/connector/v1/connect",
		GrantID:        "grant-UPG9c9GFPY3Z",
		TokenID:        "token-C6_j48B9",
		Token:          strings.Repeat("a", 32),
		Protocol:       "tcp",
		MaxConnections: 4,
	}
	if mutate != nil {
		mutate(&bundle)
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return BundlePrefix + base64.RawURLEncoding.EncodeToString(payload)
}

func TestParseBundleRoundTripsEveryField(t *testing.T) {
	bundle, err := ParseBundle(testBundle(t, nil))
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if bundle.GatewayURL != "wss://edge.hooshix-agent.ir/connector/v1/connect" ||
		bundle.GrantID != "grant-UPG9c9GFPY3Z" ||
		bundle.TokenID != "token-C6_j48B9" ||
		bundle.Token != strings.Repeat("a", 32) ||
		bundle.Protocol != "tcp" ||
		bundle.MaxConnections != 4 {
		t.Fatalf("bundle fields drifted: %+v", bundle)
	}
}

func TestParseBundleMatchesPanelEncoding(t *testing.T) {
	// Produced by hooshix-panel buildConnectorBundle: JSON keys snake_case,
	// unpadded base64url. The Go parser must accept the panel's exact output.
	const fromPanel = "hx1.eyJ2IjoxLCJnYXRld2F5Ijoid3NzOi8vZWRnZS5ob29zaGl4LWFnZW50LmlyL2Nvbm5lY3Rvci92MS9jb25uZWN0IiwiZ3JhbnRfaWQiOiJncmFudC1VUEc5YzlHRlBZM1oiLCJ0b2tlbl9pZCI6InRva2VuLUM2X2o0OEI5IiwidG9rZW4iOiJBYkNkRWZHaDAxMjM0NTY3ODlhYmNkZWZnaGlqa2xtLV8iLCJwcm90b2NvbCI6InRjcCIsIm1heF9jb25uZWN0aW9ucyI6NH0"
	bundle, err := ParseBundle(fromPanel)
	if err != nil {
		t.Fatalf("ParseBundle rejected a panel-built bundle: %v", err)
	}
	if bundle.Protocol != "tcp" || bundle.MaxConnections != 4 {
		t.Fatalf("unexpected overlay fields: %+v", bundle)
	}
	config := bundle.Config(DefaultConfig())
	if config.ListenAddress != "127.0.0.1:13389" || config.Protocol != "tcp" {
		t.Fatalf("bundle.Config lost defaults: %+v", config)
	}
}

func TestParseBundleRejectsMalformedInput(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"wrong prefix":     "hx2." + strings.Repeat("a", 40),
		"missing prefix":   strings.Repeat("a", 40),
		"inner whitespace": BundlePrefix + " " + strings.Repeat("a", 40),
		"not base64url":    BundlePrefix + "!!!",
		"not json":         BundlePrefix + base64.RawURLEncoding.EncodeToString([]byte("nope")),
		"bad gateway path": testBundle(t, func(b *Bundle) { b.GatewayURL = "wss://edge.hooshix-agent.ir/agent/v1/connect" }),
		"http gateway":     testBundle(t, func(b *Bundle) { b.GatewayURL = "https://edge.hooshix-agent.ir/connector/v1/connect" }),
		"short token":      testBundle(t, func(b *Bundle) { b.Token = "short" }),
		"whitespace token": testBundle(t, func(b *Bundle) { b.Token = strings.Repeat("a", 31) + "\n" }),
		"bad protocol":     testBundle(t, func(b *Bundle) { b.Protocol = "sctp" }),
		"negative conns":   testBundle(t, func(b *Bundle) { b.MaxConnections = -1 }),
		"too many conns":   testBundle(t, func(b *Bundle) { b.MaxConnections = 17 }),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBundle(raw); err == nil {
				t.Fatalf("ParseBundle(%q) succeeded, want rejection", raw)
			}
		})
	}
}

func TestParseBundleToleratesSurroundingWhitespace(t *testing.T) {
	raw := "  " + testBundle(t, nil) + "\r\n"
	if _, err := ParseBundle(raw); err != nil {
		t.Fatalf("paste-with-whitespace rejected: %v", err)
	}
}
