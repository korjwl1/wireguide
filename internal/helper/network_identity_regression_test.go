package helper

import (
	"github.com/korjwl1/wireguide/internal/wifi"
	"strings"
	"testing"
)

// R1: Windows probe shape (iface always "", IsWiFiInterface always true).
// On wired Ethernet the SSID is blank, so identityKnown is false forever and
// pruneManualOverrides never runs: a latch made on wired network A survives
// a settled move to a different wired network B, and automation stays
// blocked there.
func TestReview52_WindowsWiredLatchNeverClears(t *testing.T) {
	p := &netProbeResult{
		Gateway: "10.0.0.1", Iface: "", GatewayMAC: "aa:aa:aa:aa:aa:01",
		PrimaryIsWiFi: true, // iface == "" -> treated as Wi-Fi
	}
	stubNetwork(t, p)
	h, clk := newAutomationHelper(t, "")
	h.done = make(chan struct{})
	writeAutomation(t, h, map[string][]wifi.Rule{
		"T": {{When: wifi.Condition{Type: wifi.CondNetwork, GatewayMAC: "bb:bb:bb:bb:bb:02"}, Do: wifi.ActionConnect}},
	})
	clk.Advance(wifi.NegationSettleWindow * 4)
	h.recordManualOverride("T", true) // user turns T off at office (wired)

	// Move to a different wired network and stay there well past settle.
	p.Gateway, p.GatewayMAC = "10.1.0.1", "bb:bb:bb:bb:bb:02"
	h.currentNetworkState()
	clk.Advance(wifi.NegationSettleWindow * 4)
	logs := captureLogs(t)
	h.reevaluateAutomation("test")
	if _, ok := h.manualLatchFor("T"); ok {
		t.Logf("REPRODUCED: latch from wired network A still held on settled wired network B")
	}
	if !strings.Contains(logs.String(), "tunnel store unavailable") {
		t.Errorf("DEFECT: rule 'network=B -> connect' never acts on network B; latch blocks it forever\n%s", logs)
	}
}

// R2: same-SSID network gains an IPv6 prefix (or loses one, or the gateway
// ARP entry goes missing) after the user's manual Off. The identity now
// includes subnets/gateway MAC, so the latch is cleared on the SAME network
// and automation reconnects the tunnel the user just turned off.
func TestReview52_LatchClearedBySubnetChurnOnSameNetwork(t *testing.T) {
	p := wifiProbe()
	stubNetwork(t, p)
	h, clk := newAutomationHelper(t, "Home")
	h.done = make(chan struct{})
	writeAutomation(t, h, map[string][]wifi.Rule{
		"T": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "Home"}, Do: wifi.ActionConnect}},
	})
	h.currentNetworkState()
	clk.Advance(wifi.NegationSettleWindow * 2)
	h.recordManualOverride("T", true) // manual Off on Home

	p.Subnets = []string{"192.168.50.0/24", "2001:db8:1::/64"} // SLAAC prefix arrives
	h.currentNetworkState()
	clk.Advance(wifi.NegationSettleWindow)
	logs := captureLogs(t)
	h.reevaluateAutomation("test")
	if _, ok := h.manualLatchFor("T"); !ok && strings.Contains(logs.String(), "tunnel store unavailable") {
		t.Errorf("DEFECT: manual Off on SSID Home undone on the same network after an IPv6 prefix change\n%s", logs)
	}
}

func TestKnownGatewayDisappearanceDoesNotReleaseManualOff(t *testing.T) {
	p := wifiProbe()
	stubNetwork(t, p)
	h, clk := newAutomationHelper(t, "Home")
	h.recordManualOverride("work", true)
	p.GatewayMAC = ""
	p.Subnets = []string{"192.168.50.0/24", "2001:db8:2::/64"}
	h.currentNetworkState()
	clk.Advance(wifi.NegationSettleWindow * 2)
	h.pruneManualOverrides(h.currentNetworkState())
	if _, ok := h.manualLatchFor("work"); !ok {
		t.Fatal("missing ARP/SLAAC change released manual Off")
	}
	p.GatewayMAC = "b0:38:6c:54:8b:ab"
	h.currentNetworkState()
	clk.Advance(wifi.NegationSettleWindow * 2)
	h.pruneManualOverrides(h.currentNetworkState())
	if _, ok := h.manualLatchFor("work"); !ok {
		t.Fatal("ARP recovery released manual Off")
	}
}
