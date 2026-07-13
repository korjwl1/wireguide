package wifi

import (
	"net"
	"testing"
)

func ips(ss ...string) []net.IP {
	out := make([]net.IP, 0, len(ss))
	for _, s := range ss {
		out = append(out, net.ParseIP(s))
	}
	return out
}

func TestEvaluate_SSIDDisconnectElseConnect(t *testing.T) {
	// lucidnx's canonical workflow: off on the office network, on elsewhere.
	rules := []Rule{
		{When: Condition{Type: CondSSID, SSID: "corp-wifi"}, Do: ActionDisconnect},
		{When: Condition{Type: CondNoneMatch}, Do: ActionConnect},
	}
	if got := Evaluate(rules, NetworkContext{SSID: "corp-wifi"}); got != StateDisconnect {
		t.Errorf("on corp-wifi: got %v, want disconnect", got)
	}
	if got := Evaluate(rules, NetworkContext{SSID: "home"}); got != StateConnect {
		t.Errorf("on home: got %v, want connect", got)
	}
	// SSID matching is case-insensitive.
	if got := Evaluate(rules, NetworkContext{SSID: "CORP-WIFI"}); got != StateDisconnect {
		t.Errorf("case-insensitive SSID: got %v, want disconnect", got)
	}
}

func TestEvaluate_SubnetDisconnect(t *testing.T) {
	rules := []Rule{
		{When: Condition{Type: CondSubnet, Subnet: "10.1.1.0/24"}, Do: ActionDisconnect},
		{When: Condition{Type: CondNoneMatch}, Do: ActionConnect},
	}
	if got := Evaluate(rules, NetworkContext{PhysicalIPs: ips("10.1.1.42")}); got != StateDisconnect {
		t.Errorf("inside subnet: got %v, want disconnect", got)
	}
	if got := Evaluate(rules, NetworkContext{PhysicalIPs: ips("192.168.0.5")}); got != StateConnect {
		t.Errorf("outside subnet: got %v, want connect", got)
	}
}

func TestEvaluate_NetworkGatewayMAC(t *testing.T) {
	// Two homes both on 192.168.0.0/24 but with different routers — the
	// gateway-MAC fingerprint disambiguates them where subnet can't.
	rules := []Rule{
		{When: Condition{Type: CondNetwork, GatewayMAC: "b0:38:6c:54:8b:ab"}, Do: ActionDisconnect},
		{When: Condition{Type: CondNoneMatch}, Do: ActionConnect},
	}
	// On the fingerprinted network → disconnect (case-insensitive match).
	if got := Evaluate(rules, NetworkContext{GatewayMAC: "B0:38:6C:54:8B:AB", PhysicalIPs: ips("192.168.0.5")}); got != StateDisconnect {
		t.Errorf("matching gateway MAC: got %v, want disconnect", got)
	}
	// A different router on the SAME subnet → not matched → connect.
	if got := Evaluate(rules, NetworkContext{GatewayMAC: "aa:bb:cc:dd:ee:ff", PhysicalIPs: ips("192.168.0.5")}); got != StateConnect {
		t.Errorf("different gateway MAC, same subnet: got %v, want connect", got)
	}
	// Unknown gateway MAC → does not match.
	if got := Evaluate(rules, NetworkContext{GatewayMAC: ""}); got != StateConnect {
		t.Errorf("empty gateway MAC: got %v, want connect", got)
	}
	// Separator/case variants of the SAME MAC must all match — users
	// paste dashes, no separators, upper-case, etc.
	for _, variant := range []string{"B0-38-6C-54-8B-AB", "b0386c548bab", "B0:38:6C:54:8B:AB", "b0-38-6c-54-8b-ab"} {
		vr := []Rule{
			{When: Condition{Type: CondNetwork, GatewayMAC: variant}, Do: ActionDisconnect},
			{When: Condition{Type: CondNoneMatch}, Do: ActionConnect},
		}
		if got := Evaluate(vr, NetworkContext{GatewayMAC: "b0:38:6c:54:8b:ab"}); got != StateDisconnect {
			t.Errorf("MAC variant %q should match canonical form: got %v", variant, got)
		}
	}
}

func TestEvaluate_FirstConcreteMatchWins(t *testing.T) {
	rules := []Rule{
		{When: Condition{Type: CondSSID, SSID: "a"}, Do: ActionConnect},
		{When: Condition{Type: CondSSID, SSID: "a"}, Do: ActionDisconnect}, // shadowed
	}
	if got := Evaluate(rules, NetworkContext{SSID: "a"}); got != StateConnect {
		t.Errorf("first match should win: got %v, want connect", got)
	}
}

func TestEvaluate_ConflictTopWins(t *testing.T) {
	// Two DIFFERENT condition types that both match the same context but
	// disagree on the action — the topmost rule must win, and reordering
	// must flip the result (drag-to-reorder = priority).
	ctx := NetworkContext{
		SSID:        "office-wifi",
		GatewayMAC:  "b0:38:6c:54:8b:ab",
		PhysicalIPs: ips("192.168.0.5"),
	}
	netRule := Rule{When: Condition{Type: CondNetwork, GatewayMAC: "b0:38:6c:54:8b:ab"}, Do: ActionDisconnect}
	wifiRule := Rule{When: Condition{Type: CondSSID, SSID: "office-wifi"}, Do: ActionConnect}

	if got := Evaluate([]Rule{netRule, wifiRule}, ctx); got != StateDisconnect {
		t.Errorf("network rule on top: got %v, want disconnect", got)
	}
	if got := Evaluate([]Rule{wifiRule, netRule}, ctx); got != StateConnect {
		t.Errorf("wifi rule on top (reordered): got %v, want connect", got)
	}
}

func TestEvaluate_NoRulesOrNoMatch(t *testing.T) {
	if got := Evaluate(nil, NetworkContext{SSID: "x"}); got != StateUnmanaged {
		t.Errorf("no rules: got %v, want unmanaged", got)
	}
	// Concrete conditions present but none match, and no none_match rule.
	rules := []Rule{{When: Condition{Type: CondSSID, SSID: "a"}, Do: ActionConnect}}
	if got := Evaluate(rules, NetworkContext{SSID: "b"}); got != StateUnmanaged {
		t.Errorf("no match, no fallback: got %v, want unmanaged", got)
	}
}

func TestEvaluate_NoneMatchOnlyWhenNoConcreteMatch(t *testing.T) {
	rules := []Rule{
		{When: Condition{Type: CondSSID, SSID: "corp"}, Do: ActionDisconnect},
		{When: Condition{Type: CondNoneMatch}, Do: ActionConnect},
	}
	// Concrete matches → none_match must NOT fire.
	if got := Evaluate(rules, NetworkContext{SSID: "corp"}); got != StateDisconnect {
		t.Errorf("concrete match present: got %v, want disconnect", got)
	}
}

func TestEvaluate_InvalidSubnetIgnored(t *testing.T) {
	rules := []Rule{
		{When: Condition{Type: CondSubnet, Subnet: "not-a-cidr"}, Do: ActionDisconnect},
		{When: Condition{Type: CondNoneMatch}, Do: ActionConnect},
	}
	if got := Evaluate(rules, NetworkContext{PhysicalIPs: ips("10.1.1.1")}); got != StateConnect {
		t.Errorf("invalid subnet should not match: got %v, want connect", got)
	}
}

// none_match is unconditional AT ITS POSITION: dragged to the top it
// overrides everything below (issue #12, was previously always held to
// the end regardless of order).
func TestEvaluate_NoneMatchHonoursPosition(t *testing.T) {
	rules := []Rule{
		{When: Condition{Type: CondNoneMatch}, Do: ActionDisconnect}, // top → unconditional
		{When: Condition{Type: CondSSID, SSID: "home"}, Do: ActionConnect},
	}
	// Even on "home", the top else wins.
	if got := Evaluate(rules, NetworkContext{SSID: "home"}); got != StateDisconnect {
		t.Errorf("else at top should override: want Disconnect, got %v", got)
	}
	// Moving the concrete rule above the else restores first-match-wins.
	rules[0], rules[1] = rules[1], rules[0]
	if got := Evaluate(rules, NetworkContext{SSID: "home"}); got != StateConnect {
		t.Errorf("concrete above else: want Connect, got %v", got)
	}
}

// An unknown/empty action fails closed (rule skipped), it does not
// default to connect (issue #12).
func TestEvaluate_UnknownActionSkipped(t *testing.T) {
	rules := []Rule{
		{When: Condition{Type: CondSSID, SSID: "home"}, Do: Action("bogus")},
		{When: Condition{Type: CondNoneMatch}, Do: ActionDisconnect},
	}
	if got := Evaluate(rules, NetworkContext{SSID: "home"}); got != StateDisconnect {
		t.Errorf("unknown action must be skipped, not treated as connect: got %v", got)
	}
	// A lone invalid rule leaves the tunnel unmanaged.
	if got := Evaluate(rules[:1], NetworkContext{SSID: "home"}); got != StateUnmanaged {
		t.Errorf("lone invalid rule: want Unmanaged, got %v", got)
	}
}

func TestValidateRule(t *testing.T) {
	bad := []Rule{
		{When: Condition{Type: CondSSID, SSID: ""}, Do: ActionConnect},
		{When: Condition{Type: CondSubnet, Subnet: "not-a-cidr"}, Do: ActionConnect},
		{When: Condition{Type: CondNetwork, GatewayMAC: "zz:zz"}, Do: ActionConnect},
		{When: Condition{Type: CondSSID, SSID: "ok"}, Do: Action("nope")},
		{When: Condition{Type: "weird"}, Do: ActionConnect},
	}
	for i, r := range bad {
		if err := ValidateRule(r); err == nil {
			t.Errorf("bad rule %d should fail validation: %+v", i, r)
		}
	}
	good := []Rule{
		{When: Condition{Type: CondSSID, SSID: "home"}, Do: ActionConnect},
		{When: Condition{Type: CondSubnet, Subnet: "10.0.0.0/8"}, Do: ActionDisconnect},
		{When: Condition{Type: CondNetwork, GatewayMAC: "B0-38-6C-54-8B-AB"}, Do: ActionConnect},
		{When: Condition{Type: CondNoneMatch}, Do: ActionConnect},
	}
	for i, r := range good {
		if err := ValidateRule(r); err != nil {
			t.Errorf("good rule %d should pass: %+v: %v", i, r, err)
		}
	}
}

func TestMigrateFromLegacy(t *testing.T) {
	legacy := &Rules{
		TrustedSSIDs: []string{"corp-wifi"},
		PerTunnel: map[string]TunnelSSIDs{
			"company": {AutoConnectSSIDs: []string{"home", "cafe"}},
			"nolegacy": {},
		},
	}
	auto := MigrateFromLegacy(legacy)

	got := auto.PerTunnel["company"]
	// trusted disconnect + connect home + connect cafe (no synthesized
	// none_match — migration translates only explicit legacy settings).
	if len(got) != 3 {
		t.Fatalf("company rules: got %d, want 3 (%+v)", len(got), got)
	}
	// Trusted disconnect must come first (precedence).
	if got[0].Do != ActionDisconnect || got[0].When.SSID != "corp-wifi" {
		t.Errorf("first rule should be trusted disconnect, got %+v", got[0])
	}
	if got[1].Do != ActionConnect || got[1].When.SSID != "home" {
		t.Errorf("second rule should be connect home, got %+v", got[1])
	}
	// Migration must NOT synthesize a none_match rule.
	for _, r := range got {
		if r.When.Type == CondNoneMatch {
			t.Errorf("migration should not add a none_match rule, got %+v", r)
		}
	}
	// A tunnel with no legacy rules gets no rules.
	if _, ok := auto.PerTunnel["nolegacy"]; ok {
		t.Errorf("nolegacy should have no migrated rules")
	}

	// Behavioural check: on corp-wifi the migrated company tunnel
	// disconnects; on home it connects.
	if s := Evaluate(got, NetworkContext{SSID: "corp-wifi"}); s != StateDisconnect {
		t.Errorf("migrated: corp-wifi got %v, want disconnect", s)
	}
	if s := Evaluate(got, NetworkContext{SSID: "home"}); s != StateConnect {
		t.Errorf("migrated: home got %v, want connect", s)
	}
	// A network matching none of the tunnel's rules leaves it untouched —
	// migration no longer forces a disconnect on unlisted networks
	// (including Ethernet / no-SSID). This is the fix for the observed
	// "manually connected on Ethernet, got auto-killed" behaviour.
	if s := Evaluate(got, NetworkContext{SSID: "random-cafe"}); s != StateUnmanaged {
		t.Errorf("migrated: away network got %v, want unmanaged", s)
	}
	if s := Evaluate(got, NetworkContext{PhysicalIPs: ips("192.168.0.5")}); s != StateUnmanaged {
		t.Errorf("migrated: ethernet (no ssid) got %v, want unmanaged", s)
	}
}

func TestMigrateFromLegacy_Nil(t *testing.T) {
	auto := MigrateFromLegacy(nil)
	if auto == nil || auto.PerTunnel == nil {
		t.Fatal("nil legacy should yield an initialised empty Automation")
	}
}
