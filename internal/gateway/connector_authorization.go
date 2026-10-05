package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"time"

	contractv2 "github.com/hasanjodatshandi/HooshiXAgent/internal/contractv2"
)

var errConnectorUnauthorized = errors.New("connector authorization failed")

// authorizeConnector resolves all externally owned authority required before
// a private TCP stream may consume a Gateway slot. Every rejection collapses
// to one error so the ingress boundary cannot be used as a grant/endpoint
// existence oracle.
func authorizeConnector(
	ctx context.Context,
	metadata PrivateEndpointMetadata,
	grantID string,
	tokenID string,
	token string,
	at time.Time,
) (contractv2.ConnectorGrant, contractv2.ServiceEndpoint, error) {
	if metadata == nil || len(token) < 32 || len(token) > 512 {
		return contractv2.ConnectorGrant{}, contractv2.ServiceEndpoint{}, errConnectorUnauthorized
	}
	grant, err := metadata.ConnectorGrant(ctx, grantID, at)
	if err != nil || grant.TokenID != tokenID {
		return contractv2.ConnectorGrant{}, contractv2.ServiceEndpoint{}, errConnectorUnauthorized
	}
	digest := sha256.Sum256([]byte(token))
	expected, decodeOK := decodeSHA256(grant.TokenSHA256)
	if !decodeOK || subtle.ConstantTimeCompare(digest[:], expected[:]) != 1 {
		return contractv2.ConnectorGrant{}, contractv2.ServiceEndpoint{}, errConnectorUnauthorized
	}
	endpoint, err := metadata.ServiceEndpoint(ctx, grant.EndpointID, at)
	if err != nil || (endpoint.Protocol != contractv2.ProtocolTCP && endpoint.Protocol != contractv2.ProtocolUDP) ||
		(endpoint.Exposure != contractv2.ExposurePrivate && endpoint.Exposure != contractv2.ExposureBoth) {
		return contractv2.ConnectorGrant{}, contractv2.ServiceEndpoint{}, errConnectorUnauthorized
	}
	return grant, endpoint, nil
}

func decodeSHA256(value string) ([sha256.Size]byte, bool) {
	var digest [sha256.Size]byte
	if len(value) != sha256.Size*2 {
		return digest, false
	}
	for index := range digest {
		high, okHigh := hexNibble(value[index*2])
		low, okLow := hexNibble(value[index*2+1])
		if !okHigh || !okLow {
			return [sha256.Size]byte{}, false
		}
		digest[index] = high<<4 | low
	}
	return digest, true
}

func hexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	default:
		return 0, false
	}
}
