package wifi

import "sort"

// Rules defines WiFi auto-connect behavior. The model is per-tunnel:
// each tunnel owns the list of SSIDs that should auto-activate it.
// The "trusted" list is a global override that disconnects auto-managed
// tunnels when joining those networks.
type Rules struct {
	TrustedSSIDs []string               `json:"trusted_ssids"` // override: VPN off on these networks
	PerTunnel    map[string]TunnelSSIDs `json:"per_tunnel"`    // keyed by tunnel name
}

// TunnelSSIDs holds the per-tunnel auto-connect list. Wrapped in a
// struct (rather than just []string) so future per-tunnel fields can
// be added without changing the JSON shape.
type TunnelSSIDs struct {
	AutoConnectSSIDs []string `json:"auto_connect_ssids"`
}

// DefaultRules returns empty rules with maps initialized so
// JSON marshaling produces {} rather than null for empty per-tunnel.
func DefaultRules() *Rules {
	return &Rules{
		PerTunnel: make(map[string]TunnelSSIDs),
	}
}

// Action determines what to do when the system joins the given SSID.
// Returns:
//
//	"disconnect", ""            — SSID is trusted, drop auto-managed tunnels
//	"connect",    "tunnel-name" — SSID matches a tunnel's auto-connect list
//	"none",       ""            — no rule applies
//
// When multiple tunnels would match the same SSID, the lexicographically
// first tunnel wins. Sorting yields deterministic behavior across runs
// and makes the choice predictable for the user.
func (r *Rules) Action(ssid string) (action string, tunnelName string) {
	if ssid == "" {
		return "none", ""
	}
	for _, trusted := range r.TrustedSSIDs {
		if trusted == ssid {
			return "disconnect", ""
		}
	}
	names := make([]string, 0, len(r.PerTunnel))
	for n := range r.PerTunnel {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, s := range r.PerTunnel[name].AutoConnectSSIDs {
			if s == ssid {
				return "connect", name
			}
		}
	}
	return "none", ""
}
