package wifi

import (
	"fmt"
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
//   - Rules are examined in order and the FIRST matching, well-formed
//     rule wins — uniformly, priority == position (issue #12). This is
//     what the editor's "top rule wins, drag to reorder" promises.
//   - none_match ("else") is an unconditional match at its own position,
//     so it acts as a fallback when placed last and as an unconditional
//     override if dragged to the top — no special end-of-list handling.
//   - A rule with a malformed condition (bad CIDR/MAC, empty SSID) or an
//     unknown action never fires; it is skipped rather than defaulting to
//     connect. So an invalid rule fails closed (leaves the tunnel alone),
//     it doesn't silently connect.
//   - If nothing matches, the tunnel is Unmanaged (untouched).
//
// This lets the canonical workflow — "disconnect on the office network,
// connect everywhere else" — be expressed as
//
//	{when: ssid=corp,        do: disconnect}
//	{when: subnet=10/8,      do: disconnect}
//	{when: none_match,       do: connect}
func Evaluate(rules []Rule, ctx NetworkContext) DesiredState {
	for i := range rules {
		r := rules[i]
		state, ok := actionState(r.Do)
		if !ok {
			continue // unknown action → rule can't fire
		}
		if r.When.Validate() != nil {
			continue // malformed condition → rule can't fire
		}
		if ruleMatches(r.When, ctx) {
			return state
		}
	}
	return StateUnmanaged
}

// actionState maps an action to its desired state, reporting ok=false for
// an unknown/empty action so callers can skip the rule instead of
// treating anything-but-disconnect as connect.
func actionState(a Action) (DesiredState, bool) {
	switch a {
	case ActionConnect:
		return StateConnect, true
	case ActionDisconnect:
		return StateDisconnect, true
	}
	return StateUnmanaged, false
}

// ruleMatches reports whether a (pre-validated) condition matches the
// context. none_match is unconditional at its position.
func ruleMatches(c Condition, ctx NetworkContext) bool {
	if c.Type == CondNoneMatch {
		return true
	}
	return conditionMatches(c, ctx)
}

// Validate reports whether the condition is well-formed. A malformed
// condition can never match, so save paths reject it (issue #12) and
// Evaluate skips it.
func (c Condition) Validate() error {
	switch c.Type {
	case CondSSID:
		if strings.TrimSpace(c.SSID) == "" {
			return fmt.Errorf("ssid condition requires a non-empty SSID")
		}
	case CondSubnet:
		if _, _, err := net.ParseCIDR(strings.TrimSpace(c.Subnet)); err != nil {
			return fmt.Errorf("invalid subnet %q (want CIDR like 192.168.0.0/24)", c.Subnet)
		}
	case CondNetwork:
		if canonicalMAC(c.GatewayMAC) == "" {
			return fmt.Errorf("invalid gateway MAC %q (want 12 hex digits)", c.GatewayMAC)
		}
	case CondNoneMatch:
		// always valid
	default:
		return fmt.Errorf("unknown condition type %q", c.Type)
	}
	return nil
}

// ValidateRule checks a rule's action and condition. Used by the CLI and
// helper to reject bad rules on save rather than silently no-op'ing them.
func ValidateRule(r Rule) error {
	if _, ok := actionState(r.Do); !ok {
		return fmt.Errorf("unknown action %q (want connect or disconnect)", r.Do)
	}
	return r.When.Validate()
}

// conditionMatches reports whether a concrete (ssid/subnet/network)
// condition matches the context. none_match is handled by ruleMatches.
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
		want := canonicalMAC(c.GatewayMAC)
		got := canonicalMAC(ctx.GatewayMAC)
		return want != "" && want == got
	}
	return false
}

// canonicalMAC reduces a MAC to its bare lower-case hex digits so that
// values differing only in separator (":" vs "-" vs none) or case
// compare equal — users paste MACs in every style. Returns "" when there
// aren't exactly 12 hex digits (malformed / empty), which never matches.
func canonicalMAC(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			b.WriteRune(r)
		case r >= 'A' && r <= 'F':
			b.WriteRune(r + ('a' - 'A'))
		}
	}
	hex := b.String()
	if len(hex) != 12 {
		return ""
	}
	return hex
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
