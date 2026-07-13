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

func TestEvaluate_FirstConcreteMatchWins(t *testing.T) {
	rules := []Rule{
		{When: Condition{Type: CondSSID, SSID: "a"}, Do: ActionConnect},
		{When: Condition{Type: CondSSID, SSID: "a"}, Do: ActionDisconnect}, // shadowed
	}
	if got := Evaluate(rules, NetworkContext{SSID: "a"}); got != StateConnect {
		t.Errorf("first match should win: got %v, want connect", got)
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
}

func TestMigrateFromLegacy_Nil(t *testing.T) {
	auto := MigrateFromLegacy(nil)
	if auto == nil || auto.PerTunnel == nil {
		t.Fatal("nil legacy should yield an initialised empty Automation")
	}
}
