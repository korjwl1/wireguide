package config

import "github.com/korjwl1/wireguide/internal/domain"

// The domain types live in internal/domain — this package re-exports them as
// type aliases so existing callers (parser, validator, serializer, and legacy
// imports) keep compiling. New code should prefer the domain package directly.
type (
	WireGuardConfig = domain.WireGuardConfig
	InterfaceConfig = domain.InterfaceConfig
	PeerConfig      = domain.PeerConfig
	Script          = domain.Script
)
