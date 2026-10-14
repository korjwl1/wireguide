package wifi

import (
	"encoding/json"
	"testing"
)

// settledCtx is a settled, online Wi-Fi context.
func settledCtx(ssid string) NetworkContext {
	return NetworkContext{SSID: ssid, Settled: true, Online: true, PrimaryIface: "en0", PrimaryIsWiFi: true}
}

func negSSID(ssid string, do Action) Rule {
	return Rule{When: Condition{Type: CondSSID, Negate: true, SSID: ssid}, Do: do}
}
func posSSID(ssid string, do Action) Rule {
	return Rule{When: Condition{Type: CondSSID, SSID: ssid}, Do: do}
}
func elseRule(do Action) Rule { return Rule{When: Condition{Type: CondNoneMatch}, Do: do} }

func TestNegatedSSID_Basic(t *testing.T) {
	rules := []Rule{negSSID("P", ActionConnect)}
	for _, tc := range []struct {
		ssid string
		want DesiredState
	}{
		{"X", StateConnect},
		{"P", StateUnmanaged},
		{"p", StateUnmanaged},
		{" P ", StateUnmanaged}, // trimmed
	} {
		if got := Evaluate(rules, settledCtx(tc.ssid)); got != tc.want {
			t.Errorf("ssid %q: got %v want %v", tc.ssid, got, tc.want)
		}
	}
}

func TestNegatedSSID_RuleSSIDTrimmed(t *testing.T) {
	rules := []Rule{negSSID("P ", ActionConnect)}
	if got := Evaluate(rules, settledCtx("P")); got != StateUnmanaged {
		t.Errorf("trailing space in rule SSID must not make negation always-true: got %v", got)
	}
}

func TestNegatedSSID_EmptyOnWiFiHolds(t *testing.T) {
	rules := []Rule{negSSID("P", ActionConnect)}
	got, info := EvaluateDetailed(rules, settledCtx(""))
	if got != StateUnmanaged || !info.Held || info.RuleIndex != 0 {
		t.Errorf("got %v %+v, want held unmanaged at 0", got, info)
	}
}

func TestNegatedSSID_EmptyOnNonWiFiMatches(t *testing.T) {
	rules := []Rule{negSSID("P", ActionConnect)}
	ctx := NetworkContext{Settled: true, Online: true, PrimaryIface: "en5", PrimaryIsWiFi: false}
	if got := Evaluate(rules, ctx); got != StateConnect {
		t.Errorf("ethernet no SSID: got %v want connect", got)
	}
	// Unknown primary interface -> hold.
	ctx.PrimaryIface = ""
	if got := Evaluate(rules, ctx); got != StateUnmanaged {
		t.Errorf("unknown primary: got %v want unmanaged", got)
	}
	// Not settled -> hold.
	ctx = NetworkContext{Settled: false, Online: true, PrimaryIface: "en5"}
	if got := Evaluate(rules, ctx); got != StateUnmanaged {
		t.Errorf("unsettled: got %v want unmanaged", got)
	}
	// Offline -> hold.
	ctx = NetworkContext{Settled: true, Online: false, PrimaryIface: "en5"}
	if got := Evaluate(rules, ctx); got != StateUnmanaged {
		t.Errorf("offline: got %v want unmanaged", got)
	}
}

func TestNegated_UnsettledHolds(t *testing.T) {
	ctx := settledCtx("X")
	ctx.Settled = false
	if got := Evaluate([]Rule{negSSID("P", ActionConnect)}, ctx); got != StateUnmanaged {
		t.Errorf("got %v want unmanaged", got)
	}
}

func TestEvaluate_RoamNegateNoFlap(t *testing.T) {
	rules := []Rule{posSSID("P", ActionDisconnect), negSSID("P", ActionConnect)}
	want := []DesiredState{StateDisconnect, StateUnmanaged, StateDisconnect}
	for i, ssid := range []string{"P", "", "P"} {
		if got := Evaluate(rules, settledCtx(ssid)); got != want[i] {
			t.Errorf("step %d (%q): got %v want %v", i, ssid, got, want[i])
		}
	}
}

func TestEvaluate_RoamElseFlapCharacterization(t *testing.T) {
	rules := []Rule{posSSID("P", ActionDisconnect), elseRule(ActionConnect)}
	want := []DesiredState{StateDisconnect, StateConnect, StateDisconnect}
	for i, ssid := range []string{"P", "", "P"} {
		if got := Evaluate(rules, settledCtx(ssid)); got != want[i] {
			t.Errorf("step %d (%q): got %v want %v", i, ssid, got, want[i])
		}
	}
}

func TestNegated_HoldStopsFallThrough(t *testing.T) {
	rules := []Rule{negSSID("P", ActionConnect), elseRule(ActionDisconnect)}
	if got := Evaluate(rules, settledCtx("")); got != StateUnmanaged {
		t.Errorf("blank: got %v want unmanaged", got)
	}
	unsettled := settledCtx("X")
	unsettled.Settled = false
	if got := Evaluate(rules, unsettled); got != StateUnmanaged {
		t.Errorf("unsettled X: got %v want unmanaged", got)
	}
	if got := Evaluate(rules, settledCtx("X")); got != StateConnect {
		t.Errorf("settled X: got %v want connect", got)
	}
	if got := Evaluate(rules, settledCtx("P")); got != StateDisconnect {
		t.Errorf("settled P: got %v want disconnect", got)
	}
}

func TestPositiveRulesNotGatedBySettle(t *testing.T) {
	rules := []Rule{posSSID("P", ActionDisconnect), negSSID("P", ActionConnect)}
	ctx := settledCtx("P")
	ctx.Settled = false
	ctx.Online = false
	if got := Evaluate(rules, ctx); got != StateDisconnect {
		t.Errorf("got %v want disconnect", got)
	}
}

func TestNegatedSubnet(t *testing.T) {
	rule := func(do Action) Rule {
		return Rule{When: Condition{Type: CondSubnet, Negate: true, Subnet: "10.1.1.0/24"}, Do: do}
	}
	rules := []Rule{rule(ActionConnect)}
	ctx := func(ip ...string) NetworkContext {
		return NetworkContext{PhysicalIPs: ips(ip...), Settled: true, Online: true}
	}
	if got := Evaluate(rules, ctx("10.1.1.42")); got != StateUnmanaged {
		t.Errorf("inside: got %v", got)
	}
	if got := Evaluate(rules, ctx("192.168.0.5")); got != StateConnect {
		t.Errorf("outside: got %v", got)
	}
	if got := Evaluate(rules, ctx("10.1.1.42", "192.168.0.5")); got != StateUnmanaged {
		t.Errorf("mixed: got %v", got)
	}
	if got, info := EvaluateDetailed(rules, ctx()); got != StateUnmanaged || !info.Held {
		t.Errorf("empty IPs: got %v %+v, want held", got, info)
	}
	un := ctx("192.168.0.5")
	un.Settled = false
	if got, info := EvaluateDetailed(rules, un); got != StateUnmanaged || !info.Held {
		t.Errorf("unsettled: got %v %+v, want held", got, info)
	}
}

func TestNegatedNetwork(t *testing.T) {
	rules := []Rule{{When: Condition{Type: CondNetwork, Negate: true, GatewayMAC: "b0:38:6c:54:8b:ab"}, Do: ActionConnect}}
	ctx := func(mac string) NetworkContext {
		return NetworkContext{GatewayMAC: mac, Settled: true, Online: true}
	}
	for _, same := range []string{"B0:38:6C:54:8B:AB", "b0-38-6c-54-8b-ab", "b0386c548bab"} {
		if got := Evaluate(rules, ctx(same)); got != StateUnmanaged {
			t.Errorf("same MAC %q: got %v", same, got)
		}
	}
	if got := Evaluate(rules, ctx("aa:bb:cc:dd:ee:ff")); got != StateConnect {
		t.Errorf("different MAC: got %v", got)
	}
	if got, info := EvaluateDetailed(rules, ctx("")); got != StateUnmanaged || !info.Held {
		t.Errorf("empty MAC: got %v %+v, want held", got, info)
	}
}

func TestNoneMatchNegateInvalid(t *testing.T) {
	r := Rule{When: Condition{Type: CondNoneMatch, Negate: true}, Do: ActionConnect}
	if ValidateRule(r) == nil {
		t.Error("negated none_match must fail validation")
	}
	if got := Evaluate([]Rule{r}, settledCtx("X")); got != StateUnmanaged {
		t.Errorf("negated none_match must be skipped: got %v", got)
	}
	if got := Evaluate([]Rule{r, posSSID("X", ActionConnect)}, settledCtx("X")); got != StateConnect {
		t.Errorf("rule after skipped one must be reached: got %v", got)
	}
}

func TestValidateRule_Negated(t *testing.T) {
	bad := []Rule{
		{When: Condition{Type: CondSSID, Negate: true, SSID: "  "}, Do: ActionConnect},
		{When: Condition{Type: CondSubnet, Negate: true, Subnet: "nope"}, Do: ActionConnect},
		{When: Condition{Type: CondNetwork, Negate: true, GatewayMAC: "zz"}, Do: ActionConnect},
	}
	for i, r := range bad {
		if ValidateRule(r) == nil {
			t.Errorf("bad[%d] should fail", i)
		}
	}
	good := []Rule{
		negSSID("P", ActionConnect),
		{When: Condition{Type: CondSubnet, Negate: true, Subnet: "10.0.0.0/8"}, Do: ActionDisconnect},
		{When: Condition{Type: CondNetwork, Negate: true, GatewayMAC: "b0:38:6c:54:8b:ab"}, Do: ActionConnect},
	}
	for i, r := range good {
		if err := ValidateRule(r); err != nil {
			t.Errorf("good[%d]: %v", i, err)
		}
	}
}

func TestMalformedActionSkippedBeforeNegatedHold(t *testing.T) {
	rules := []Rule{negSSID("P", Action("bogus")), elseRule(ActionDisconnect)}
	if got := Evaluate(rules, settledCtx("")); got != StateDisconnect {
		t.Errorf("got %v want disconnect", got)
	}
}

func TestConditionJSON_Negate(t *testing.T) {
	b, _ := json.Marshal(Condition{Type: CondSSID, Negate: true, SSID: "P"})
	if string(b) != `{"type":"ssid","negate":true,"ssid":"P"}` {
		t.Errorf("negated marshal: %s", b)
	}
	b, _ = json.Marshal(Condition{Type: CondSSID, SSID: "P"})
	if string(b) != `{"type":"ssid","ssid":"P"}` {
		t.Errorf("non-negated marshal: %s", b)
	}
	var c Condition
	if err := json.Unmarshal([]byte(`{"type":"ssid","ssid":"CafeWiFi"}`), &c); err != nil || c.Negate {
		t.Errorf("legacy parse: %v %+v", err, c)
	}
}

func TestAutomationJSON_RoundTripByteIdentical(t *testing.T) {
	in := `{"per_tunnel_rules":{"home-vpn":[{"when":{"type":"ssid","ssid":"CafeWiFi"},"do":"connect"}]}}`
	var a Automation
	if err := json.Unmarshal([]byte(in), &a); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(&a)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != in {
		t.Errorf("round trip changed bytes:\n in: %s\nout: %s", in, out)
	}
	// The bare per-tunnel shape from the user's config.
	rin := `{"home-vpn":[{"when":{"type":"ssid","ssid":"CafeWiFi"},"do":"connect"}]}`
	var m map[string][]Rule
	if err := json.Unmarshal([]byte(rin), &m); err != nil {
		t.Fatal(err)
	}
	rout, _ := json.Marshal(m)
	if string(rout) != rin {
		t.Errorf("map round trip changed bytes:\n in: %s\nout: %s", rin, rout)
	}
}

func TestMigrateFromLegacy_NoNegate(t *testing.T) {
	a := MigrateFromLegacy(&Rules{
		TrustedSSIDs: []string{"office"},
		PerTunnel:    map[string]TunnelSSIDs{"t": {AutoConnectSSIDs: []string{"home"}}},
	})
	for _, r := range a.PerTunnel["t"] {
		if r.When.Negate {
			t.Errorf("migrated rule negated: %+v", r)
		}
	}
}

func TestHasNegated(t *testing.T) {
	if HasNegated([]Rule{posSSID("P", ActionConnect)}) {
		t.Error("positive only")
	}
	if !HasNegated([]Rule{posSSID("P", ActionConnect), negSSID("P", ActionConnect)}) {
		t.Error("has negated")
	}
}
