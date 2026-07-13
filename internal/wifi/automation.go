package wifi

import (
	"net"
	"sort"
	"strings"
)

// Automation is the per-tunnel condition→action rule model that
// generalises the older TrustedSSIDs + AutoConnectSSIDs pair (issue #12).
// Each tunnel owns an ordered list of rules; evaluation decides, from the
// current network context, whether that tunnel should be connected or
// disconnected — independently of how it was brought up.
//
// This type is additive: the legacy Rules (TrustedSSIDs / PerTunnel
// AutoConnectSSIDs) still exist for migration. MigrateFromLegacy builds
// an equivalent Automation from a legacy Rules value.
type Automation struct {
	// PerTunnel maps a tunnel name to its ordered rule list.
	PerTunnel map[string][]Rule `json:"per_tunnel_rules"`
}

// Rule is one condition→action pair.
type Rule struct {
	When Condition `json:"when"`
	Do   Action    `json:"do"`
}

// Action is what a matched rule does to its tunnel.
type Action string

const (
	ActionConnect    Action = "connect"
	ActionDisconnect Action = "disconnect"
)

// Condition types.
const (
	CondSSID      = "ssid"       // current Wi-Fi SSID equals SSID
	CondSubnet    = "subnet"     // a physical-interface address is inside Subnet (CIDR)
	CondNetwork   = "network"    // the default gateway's MAC equals GatewayMAC
	CondNoneMatch = "none_match" // none of this tunnel's concrete conditions matched
)

// Condition is a single match predicate. Only the field relevant to Type
// is used.
type Condition struct {
	Type   string `json:"type"`
	SSID   string `json:"ssid,omitempty"`
	Subnet string `json:"subnet,omitempty"` // CIDR, e.g. "10.0.0.0/24"
	// GatewayMAC fingerprints a SPECIFIC network by its default-gateway
	// (router) MAC address — precise and medium-agnostic, so it
	// disambiguates two different networks that share a common subnet
	// like 192.168.0.0/24. Lower-cased colon form, e.g. "b0:38:6c:...".
	GatewayMAC string `json:"gateway_mac,omitempty"`
	// Label is a human-readable hint shown in the editor for a network
	// condition (e.g. "Office · 192.168.0.0/24"). Not used for matching.
	Label string `json:"label,omitempty"`
}

// NetworkContext is the current network state a rule set is evaluated
// against.
type NetworkContext struct {
	SSID string // current Wi-Fi SSID ("" when not on Wi-Fi / unknown)
	// PhysicalIPs are the IP addresses currently assigned to physical
	// (non-tunnel) interfaces. Used for subnet conditions.
	PhysicalIPs []net.IP
	// GatewayMAC is the current default gateway's MAC ("" if unknown).
	// Used for network conditions.
	GatewayMAC string
}

// DefaultAutomation returns an empty Automation with the map initialised
// so JSON marshals to {} rather than null.
func DefaultAutomation() *Automation {
	return &Automation{PerTunnel: make(map[string][]Rule)}
}

// DesiredState is the outcome of evaluating one tunnel's rules.
type DesiredState int

const (
	// StateUnmanaged means no rule applied — leave the tunnel exactly as
	// it is (never auto-touch it).
	StateUnmanaged DesiredState = iota
	StateConnect
	StateDisconnect
)

// Evaluate decides the desired state for a single tunnel given the
// current network context. Semantics:
//
//   - Rules are examined in order. The FIRST rule whose concrete
//     condition (ssid or subnet) matches wins, and its action is the
//     result.
//   - none_match rules are held aside; if NO concrete condition in the
//     list matched, the first none_match rule's action applies.
//   - If nothing matches, the tunnel is Unmanaged (untouched).
//
// This lets the canonical workflow — "disconnect on the office network,
// connect everywhere else" — be expressed as
//
//	{when: ssid=corp,        do: disconnect}
//	{when: subnet=10/8,      do: disconnect}
//	{when: none_match,       do: connect}
func Evaluate(rules []Rule, ctx NetworkContext) DesiredState {
	var noneMatchAction *Action
	for i := range rules {
		r := rules[i]
		switch r.When.Type {
		case CondNoneMatch:
			if noneMatchAction == nil {
				a := r.Do
				noneMatchAction = &a
			}
		case CondSSID, CondSubnet, CondNetwork:
			if conditionMatches(r.When, ctx) {
				return actionToState(r.Do)
			}
		}
	}
	if noneMatchAction != nil {
		return actionToState(*noneMatchAction)
	}
	return StateUnmanaged
}

func actionToState(a Action) DesiredState {
	if a == ActionDisconnect {
		return StateDisconnect
	}
	return StateConnect
}

// conditionMatches reports whether a concrete (ssid/subnet) condition
// matches the context. none_match is handled by the caller.
func conditionMatches(c Condition, ctx NetworkContext) bool {
	switch c.Type {
	case CondSSID:
		return ctx.SSID != "" && ssidEqual(c.SSID, ctx.SSID)
	case CondSubnet:
		_, network, err := net.ParseCIDR(strings.TrimSpace(c.Subnet))
		if err != nil {
			return false
		}
		for _, ip := range ctx.PhysicalIPs {
			if network.Contains(ip) {
				return true
			}
		}
	case CondNetwork:
		return ctx.GatewayMAC != "" && strings.EqualFold(strings.TrimSpace(c.GatewayMAC), ctx.GatewayMAC)
	}
	return false
}

// TunnelNames returns the rule set's tunnel names in deterministic
// (sorted) order.
func (a *Automation) TunnelNames() []string {
	names := make([]string, 0, len(a.PerTunnel))
	for n := range a.PerTunnel {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// MigrateFromLegacy builds an Automation equivalent to a legacy Rules
// value, so existing users keep working after the model change:
//
//   - each tunnel's AutoConnectSSIDs → {when ssid=X, do connect}
//   - global TrustedSSIDs → for every tunnel that has any rule, a
//     {when ssid=Y, do disconnect} placed BEFORE its connect rules so
//     "trusted" wins over "auto-connect" on an overlapping network
//     (matching the legacy precedence where trusted was checked first).
//
// Trusted SSIDs are only meaningful relative to a tunnel that could
// otherwise be connected, so they're attached to tunnels that have
// auto-connect rules; a tunnel with no legacy rules gets none.
func MigrateFromLegacy(legacy *Rules) *Automation {
	out := DefaultAutomation()
	if legacy == nil {
		return out
	}
	names := make([]string, 0, len(legacy.PerTunnel))
	for n := range legacy.PerTunnel {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		var connectRules []Rule
		for _, ssid := range legacy.PerTunnel[name].AutoConnectSSIDs {
			if ssid == "" {
				continue
			}
			connectRules = append(connectRules, Rule{
				When: Condition{Type: CondSSID, SSID: ssid},
				Do:   ActionConnect,
			})
		}
		// Trusted SSIDs only ever affected auto-managed tunnels in the
		// legacy model, i.e. tunnels with an auto-connect list. Don't
		// attach trusted-disconnect rules to a tunnel that had no
		// connect rules — that would newly disconnect it on a trusted
		// network, which legacy never did.
		if len(connectRules) == 0 {
			continue
		}
		var rules []Rule
		// Trusted (disconnect) rules first, so they take precedence over
		// the connect rules on an overlapping network.
		for _, ssid := range legacy.TrustedSSIDs {
			if ssid == "" {
				continue
			}
			rules = append(rules, Rule{
				When: Condition{Type: CondSSID, SSID: ssid},
				Do:   ActionDisconnect,
			})
		}
		rules = append(rules, connectRules...)
		// NOTE: we deliberately do NOT synthesize a none_match→disconnect
		// rule here. Legacy auto-connect implicitly disconnected the
		// tunnel when you left its Wi-Fi zone, but that behaviour was
		// coarse (Wi-Fi-transition only, auto-managed only) and, ported
		// literally into the new any-network-change engine, would
		// aggressively tear down tunnels on Ethernet or after a manual
		// connect. Migration therefore translates only what the user
		// EXPLICITLY configured (connect on SSID, disconnect on trusted
		// SSID); a user who wants "off when I leave" adds that rule
		// explicitly in the Automation editor, alongside separate
		// connect/disconnect conditions.
		out.PerTunnel[name] = rules
	}
	return out
}
