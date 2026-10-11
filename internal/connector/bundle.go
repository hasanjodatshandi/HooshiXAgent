package connector

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// BundlePrefix versions the packed Connector invitation format. A future
// incompatible shape gets its own prefix instead of breaking this one.
const BundlePrefix = "hx1."

// Bundle is the unpacked form of a Connector invitation: everything the
// connecting user needs in one string, issued by the Panel next to a grant.
// The bundle carries the raw token and is exactly as sensitive as the token.
type Bundle struct {
	GatewayURL     string `json:"gateway"`
	GrantID        string `json:"grant_id"`
	TokenID        string `json:"token_id"`
	Token          string `json:"token"`
	Protocol       string `json:"protocol"`
	MaxConnections int    `json:"max_connections"`
}

// ParseBundle decodes and strictly validates a Connector bundle. Every field
// is re-checked against the same contract rules Config.Validate applies, so a
// bundle can never smuggle a config the CLI itself would have refused.
func ParseBundle(raw string) (Bundle, error) {
	// Bundles are pasted by hand: tolerate surrounding whitespace (a trailing
	// newline from the browser is normal), but never anything inside.
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, BundlePrefix) {
		return Bundle{}, fmt.Errorf("connect bundle must start with %q", BundlePrefix)
	}
	encoded := strings.TrimPrefix(raw, BundlePrefix)
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Bundle{}, fmt.Errorf("connect bundle payload is not valid base64url: %w", err)
	}
	var bundle Bundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		return Bundle{}, fmt.Errorf("connect bundle payload is not valid JSON: %w", err)
	}
	config := bundle.Config(DefaultConfig())
	if err := config.Validate(); err != nil {
		return Bundle{}, fmt.Errorf("connect bundle is invalid: %w", err)
	}
	return bundle, nil
}

// Config overlays the bundle onto defaults so every field the bundle does not
// set keeps its documented default.
func (bundle Bundle) Config(base Config) Config {
	base.GatewayURL = bundle.GatewayURL
	base.GrantID = bundle.GrantID
	base.TokenID = bundle.TokenID
	base.Token = bundle.Token
	if bundle.Protocol != "" {
		base.Protocol = bundle.Protocol
	}
	if bundle.MaxConnections != 0 {
		base.MaxConnections = bundle.MaxConnections
	}
	return base
}

// ErrBundleExclusive marks connection flags given together with -bundle.
var ErrBundleExclusive = errors.New("-bundle cannot be combined with -gateway, -grant-id, -token-id, or -token-file")
