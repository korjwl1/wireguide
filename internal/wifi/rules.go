package wifi

import (
	"sort"
	"strings"
)

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
	// SSID matching uses case-insensitive comparison. The 802.11 standard
	// is case-sensitive, but different OS Wi-Fi stacks normalize SSIDs
	// inconsistently (some upper-case the first letter, some preserve
	// vendor-broadcast capitalization). Users who type "MyWifi" into the
	// rule list expect it to match a SSID broadcast as "mywifi" — the
	// rare case where two real networks differ only in case is not worth
	// the surprise factor of strict matching.
	for _, trusted := range r.TrustedSSIDs {
		if ssidEqual(trusted, ssid) {
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
			if ssidEqual(s, ssid) {
				return "connect", name
			}
		}
	}
	return "none", ""
}

// ssidEqual compares two SSIDs case-insensitively. EqualFold handles
// Unicode-aware case folding (Turkish dotted I, German ß, etc.) which
// matters when SSIDs contain non-ASCII characters.
func ssidEqual(a, b string) bool {
	return strings.EqualFold(a, b)
}
