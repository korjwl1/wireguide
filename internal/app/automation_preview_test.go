package app

import (
	"testing"

	"github.com/korjwl1/wireguide/internal/automation"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
)

func ssidRule(ssid string, negate bool, do automation.Action) automation.Rule {
	return automation.Rule{When: automation.Condition{Type: automation.CondSSID, SSID: ssid, Negate: negate}, Do: do}
}

func verdictFor(t *testing.T, p AutomationPreview, name string) AutomationVerdict {
	t.Helper()
	for _, v := range p.Tunnels {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("no verdict for %q", name)
	return AutomationVerdict{}
}

func TestBuildAutomationPreview_SSIDUnknownOnlyOnKnownWiFi(t *testing.T) {
	cases := []struct {
		name string
		resp ipc.AutomationPreviewResponse
		want bool
	}{
		{"wifi no ssid", ipc.AutomationPreviewResponse{Online: true, PrimaryIface: "en0", PrimaryIsWiFi: true}, true},
		{"offline", ipc.AutomationPreviewResponse{Online: false, PrimaryIface: "en0", PrimaryIsWiFi: true}, false},
		{"unknown iface", ipc.AutomationPreviewResponse{Online: true}, false},
		{"ethernet", ipc.AutomationPreviewResponse{Online: true, PrimaryIface: "en5"}, false},
		{"has ssid", ipc.AutomationPreviewResponse{SSID: "HomeWiFi", Online: true, PrimaryIface: "en0", PrimaryIsWiFi: true}, false},
	}
	for _, c := range cases {
		p := buildAutomationPreview(c.resp, nil, nil)
		if p.SSIDUnknown != c.want {
			t.Errorf("%s: SSIDUnknown=%v want %v", c.name, p.SSIDUnknown, c.want)
		}
		if !p.Available {
			t.Errorf("%s: not available", c.name)
		}
	}
	if p := buildAutomationPreview(ipc.AutomationPreviewResponse{Online: true}, nil, nil); p.PrimaryKnown {
		t.Error("unknown iface must not be PrimaryKnown")
	}
}

func TestBuildAutomationPreview_VerdictsAndDecidingRule(t *testing.T) {
	rules := map[string][]automation.Rule{
		"home-vpn":   {ssidRule("CafeWiFi", false, automation.ActionDisconnect), ssidRule("HomeWiFi", false, automation.ActionConnect)},
		"office-vpn": {ssidRule("Corp", true, automation.ActionConnect)},
		"other-vpn":  {ssidRule("Nowhere", false, automation.ActionConnect)},
	}
	resp := ipc.AutomationPreviewResponse{
		SSID: "HomeWiFi", Online: true, Settled: true, PrimaryIface: "en0", PrimaryIsWiFi: true,
		Tunnels: []ipc.AutomationTunnelDecision{
			{Name: "home-vpn", Decision: "connect", RuleCount: 2},
			{Name: "office-vpn", Decision: "connect", RuleCount: 1},
			{Name: "other-vpn", Decision: "unmanaged", RuleCount: 1},
		},
	}
	p := buildAutomationPreview(resp, rules, nil)
	if !p.HasNegatedRules {
		t.Error("expected HasNegatedRules")
	}
	h := verdictFor(t, p, "home-vpn")
	if h.Verdict != VerdictConnect || h.RuleIndex != 2 || h.RuleType != automation.CondSSID || h.RuleValue != "HomeWiFi" || h.RuleNegate {
		t.Errorf("home-vpn: %+v", h)
	}
	o := verdictFor(t, p, "office-vpn")
	if o.RuleIndex != 1 || !o.RuleNegate || o.RuleValue != "Corp" {
		t.Errorf("office-vpn: %+v", o)
	}
	n := verdictFor(t, p, "other-vpn")
	if n.Verdict != VerdictNoMatch || n.RuleIndex != 0 || n.RuleType != "" || n.RuleValue != "" {
		t.Errorf("other-vpn: %+v", n)
	}
}

func TestBuildAutomationPreview_NetworkRuleUsesLabel(t *testing.T) {
	rules := map[string][]automation.Rule{"v": {{
		When: automation.Condition{Type: automation.CondNetwork, GatewayMAC: "aa:bb:cc:dd:ee:ff", Label: "Office"},
		Do:   automation.ActionConnect,
	}}}
	resp := ipc.AutomationPreviewResponse{
		GatewayMAC: "aa:bb:cc:dd:ee:ff", Online: true, Settled: true, PrimaryIface: "en5",
		Tunnels: []ipc.AutomationTunnelDecision{{Name: "v", Decision: "connect"}},
	}
	v := verdictFor(t, buildAutomationPreview(resp, rules, nil), "v")
	if v.RuleType != automation.CondNetwork || v.RuleValue != "Office" {
		t.Errorf("%+v", v)
	}
}

func TestBuildAutomationPreview_HeldLatchedBlocked(t *testing.T) {
	rules := map[string][]automation.Rule{
		"held-vpn": {ssidRule("Corp", true, automation.ActionConnect)},
		"a":        {ssidRule("HomeWiFi", false, automation.ActionConnect)},
		"b":        {ssidRule("HomeWiFi", false, automation.ActionConnect)},
		"c":        {ssidRule("HomeWiFi", false, automation.ActionConnect)},
	}
	resp := ipc.AutomationPreviewResponse{
		SSID: "HomeWiFi", Online: true, Settled: true, PrimaryIface: "en0", PrimaryIsWiFi: true,
		Tunnels: []ipc.AutomationTunnelDecision{
			{Name: "held-vpn", Decision: "held", Held: true},
			{Name: "a", Decision: "latched", Latched: true},
			{Name: "b", Decision: "connect", Blocked: true},
			{Name: "c", Decision: "connect", Blocked: true, Active: true},
		},
	}
	overlapCalled := false
	p := buildAutomationPreview(resp, rules, func(string) (string, bool) { overlapCalled = true; return "", false })
	if got := verdictFor(t, p, "held-vpn").Verdict; got != VerdictHeld {
		t.Errorf("held: %q", got)
	}
	if got := verdictFor(t, p, "a").Verdict; got != VerdictPaused {
		t.Errorf("latched: %q", got)
	}
	if got := verdictFor(t, p, "b").Verdict; got != VerdictBlocked {
		t.Errorf("blocked: %q", got)
	}
	// An already-active tunnel is simply connected, whatever the block says.
	if got := verdictFor(t, p, "c").Verdict; got != VerdictConnect {
		t.Errorf("active+blocked: %q", got)
	}
	if overlapCalled {
		t.Error("overlap probe should not run for held/latched/blocked/active tunnels")
	}
}

func TestBuildAutomationPreview_Overlap(t *testing.T) {
	rules := map[string][]automation.Rule{"v": {ssidRule("HomeWiFi", false, automation.ActionConnect)}, "w": {ssidRule("HomeWiFi", false, automation.ActionConnect)}}
	resp := ipc.AutomationPreviewResponse{
		SSID: "HomeWiFi", Online: true, Settled: true, PrimaryIface: "en0", PrimaryIsWiFi: true,
		Tunnels: []ipc.AutomationTunnelDecision{
			{Name: "v", Decision: "connect"},
			{Name: "w", Decision: "connect", Active: true},
		},
	}
	p := buildAutomationPreview(resp, rules, func(string) (string, bool) { return "192.168.50.0/24", true })
	if v := verdictFor(t, p, "v"); v.Verdict != VerdictOverlap || v.OverlapCIDR != "192.168.50.0/24" {
		t.Errorf("v: %+v", v)
	}
	if v := verdictFor(t, p, "w"); v.Verdict != VerdictConnect {
		t.Errorf("active tunnel must not be flagged: %+v", v)
	}
}

func TestConfigLANOverlap_TableOffNeverOverlaps(t *testing.T) {
	cfg := &domain.WireGuardConfig{
		Interface: domain.InterfaceConfig{Table: "off"},
		Peers:     []domain.PeerConfig{{AllowedIPs: []string{"0.0.0.0/0"}}},
	}
	if cidr, ok := configLANOverlap(cfg); ok {
		t.Errorf("Table=off must not overlap, got %q", cidr)
	}
	cfg.Interface.Table = "OFF"
	if _, ok := configLANOverlap(cfg); ok {
		t.Error("Table=OFF (case-insensitive) must not overlap")
	}
	if _, ok := configLANOverlap(nil); ok {
		t.Error("nil config must not overlap")
	}
}
