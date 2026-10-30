package app

import (
	"net"
	"strings"

	"github.com/korjwl1/wireguide/internal/automation"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/network"
)

// AutomationPreview is the GUI-facing view of the helper's read-only
// Automation.Preview: the network the engine currently sees plus one
// verdict per rule-bearing tunnel. The strings the user reads are built
// in the frontend from these structured fields (so they go through i18n).
type AutomationPreview struct {
	// Available is false when the helper could not be asked (the frontend
	// then hides the strip instead of showing stale or wrong state).
	Available bool   `json:"available"`
	SSID      string `json:"ssid"`
	// SSIDUnknown is true only when we are online, the primary interface is
	// known to be Wi-Fi, and no SSID is readable (Location Services denied,
	// or a roam blip). An unknown interface (offline, Windows, a utun
	// default route) never counts.
	SSIDUnknown bool `json:"ssid_unknown"`
	// PrimaryKnown is true when the helper identified the default-route
	// interface; when false, PrimaryIsWiFi is only a placeholder.
	PrimaryKnown       bool `json:"primary_known"`
	PrimaryIsWiFi      bool `json:"primary_is_wifi"`
	Online             bool `json:"online"`
	Settled            bool `json:"settled"`
	SettleRemainingSec int  `json:"settle_remaining_sec"`
	// HasNegatedRules is true when any tunnel has an "is not" rule, i.e.
	// the settle window actually holds something back.
	HasNegatedRules bool                `json:"has_negated_rules"`
	Tunnels         []AutomationVerdict `json:"tunnels"`
}

// Verdict codes for AutomationVerdict.Verdict.
const (
	VerdictConnect    = "connect"
	VerdictDisconnect = "disconnect"
	VerdictHeld       = "held"
	VerdictPaused     = "paused"  // manual latch: resumes when the network changes
	VerdictOverlap    = "overlap" // would connect but AllowedIPs overlap the LAN
	VerdictBlocked    = "blocked" // loop watchdog blocked automatic reconnects
	VerdictNoMatch    = "no_match"
)

// AutomationVerdict is one tunnel's evaluated automation state.
type AutomationVerdict struct {
	Name    string `json:"name"`
	Verdict string `json:"verdict"`
	Active  bool   `json:"active"`
	// RuleIndex is the 1-based position of the deciding rule (0 = none).
	RuleIndex int `json:"rule_index,omitempty"`
	// RuleType/RuleNegate/RuleValue describe the deciding rule's condition:
	// type is ssid|subnet|network|none_match, value the SSID / CIDR / MAC
	// (or the network's label when it has one).
	RuleType    string `json:"rule_type,omitempty"`
	RuleNegate  bool   `json:"rule_negate,omitempty"`
	RuleValue   string `json:"rule_value,omitempty"`
	OverlapCIDR string `json:"overlap_cidr,omitempty"`
}

// buildAutomationPreview maps the helper's response onto the GUI shape.
// rules supplies the per-tunnel rule lists (to name the deciding rule);
// overlap reports a LAN-overlap for a tunnel that is about to connect and
// may be nil.
func buildAutomationPreview(resp ipc.AutomationPreviewResponse, rules map[string][]automation.Rule, overlap func(name string) (string, bool)) AutomationPreview {
	out := AutomationPreview{
		Available:          true,
		SSID:               resp.SSID,
		SSIDUnknown:        resp.SSID == "" && resp.Online && resp.PrimaryIface != "" && resp.PrimaryIsWiFi,
		PrimaryKnown:       resp.PrimaryIface != "",
		PrimaryIsWiFi:      resp.PrimaryIsWiFi,
		Online:             resp.Online,
		Settled:            resp.Settled,
		SettleRemainingSec: resp.SettleRemainingSec,
		Tunnels:            []AutomationVerdict{},
	}
	ctx := automation.NetworkContext{
		SSID:          resp.SSID,
		GatewayMAC:    resp.GatewayMAC,
		Settled:       resp.Settled,
		PrimaryIface:  resp.PrimaryIface,
		PrimaryIsWiFi: resp.PrimaryIsWiFi,
		Online:        resp.Online,
	}
	for _, s := range resp.PhysicalIPs {
		if ip := net.ParseIP(s); ip != nil {
			ctx.PhysicalIPs = append(ctx.PhysicalIPs, ip)
		}
	}
	for _, d := range resp.Tunnels {
		v := AutomationVerdict{Name: d.Name, Active: d.Active}
		tr := rules[d.Name]
		if automation.HasNegated(tr) {
			out.HasNegatedRules = true
		}
		// Re-evaluate locally (pure) to learn WHICH rule decided; the
		// helper's own decision stays authoritative for the verdict.
		if _, info := automation.EvaluateDetailed(tr, ctx); info.RuleIndex >= 0 && info.RuleIndex < len(tr) {
			c := tr[info.RuleIndex].When
			v.RuleIndex = info.RuleIndex + 1
			v.RuleType = c.Type
			v.RuleNegate = c.Negate
			switch c.Type {
			case automation.CondSSID:
				v.RuleValue = c.SSID
			case automation.CondSubnet:
				v.RuleValue = c.Subnet
			case automation.CondNetwork:
				v.RuleValue = c.GatewayMAC
				if c.Label != "" {
					v.RuleValue = c.Label
				}
			}
		}
		switch d.Decision {
		case "latched":
			v.Verdict = VerdictPaused
		case "held":
			v.Verdict = VerdictHeld
		case "connect":
			v.Verdict = VerdictConnect
			if !d.Active && d.Blocked {
				v.Verdict = VerdictBlocked
			} else if !d.Active && overlap != nil {
				if cidr, hit := overlap(d.Name); hit {
					v.Verdict = VerdictOverlap
					v.OverlapCIDR = cidr
				}
			}
		case "disconnect":
			v.Verdict = VerdictDisconnect
		default:
			v.Verdict = VerdictNoMatch
			v.RuleIndex, v.RuleType, v.RuleNegate, v.RuleValue = 0, "", false, ""
		}
		out.Tunnels = append(out.Tunnels, v)
	}
	return out
}

// configLANOverlap reports the first AllowedIPs entry of cfg that contains a
// current physical-interface address. A Table=off tunnel installs no routes,
// so it can never take over the LAN and never overlaps (same rule as the
// helper's automation connect gate).
func configLANOverlap(cfg *domain.WireGuardConfig) (string, bool) {
	if cfg == nil || strings.EqualFold(cfg.Interface.Table, "off") {
		return "", false
	}
	var ips []string
	for _, p := range cfg.Peers {
		ips = append(ips, p.AllowedIPs...)
	}
	cidr, _, ok := network.FirstLocalNetworkOverlap(ips)
	return cidr, ok
}

// GetAutomationPreview asks the helper for its read-only automation
// decision (the same data as `wireguide ctl automation`) so the GUI can
// explain why a tunnel is or is not being connected. On any IPC failure it
// returns Available=false rather than an error so a 2 s poll never spams
// the UI.
func (s *TunnelService) GetAutomationPreview() AutomationPreview {
	var resp ipc.AutomationPreviewResponse
	if err := s.call(ipc.MethodAutomationPreview, nil, &resp); err != nil {
		return AutomationPreview{Tunnels: []AutomationVerdict{}}
	}
	var rules map[string][]automation.Rule
	if settings, err := s.settingsStore.Load(); err == nil && settings != nil {
		settings.EnsureAutomation()
		if settings.Automation != nil {
			rules = settings.Automation.PerTunnel
		}
	}
	return buildAutomationPreview(resp, rules, func(name string) (string, bool) {
		cfg, err := s.tunnelStore.Load(name)
		if err != nil || cfg == nil {
			return "", false
		}
		return configLANOverlap(cfg)
	})
}
