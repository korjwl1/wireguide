package helper

import (
	"testing"

	"github.com/korjwl1/wireguide/internal/wifi"
)

type latchStep struct {
	ssid string
	p    netProbeResult
}

// latchHeldAfter makes a manual Off on (ssid0, p0), then settles on each
// step in turn and reports whether the latch survived.
func latchHeldAfter(t *testing.T, ssid0 string, p0 netProbeResult, steps ...latchStep) bool {
	t.Helper()
	p := p0
	stubNetwork(t, &p)
	h, clk := newAutomationHelper(t, ssid0)
	h.currentNetworkState()
	clk.Advance(wifi.NegationSettleWindow * 2)
	h.recordManualOverride("T", true)
	for _, s := range steps {
		p = s.p
		h.wifiMon.ReportExternalSSID(s.ssid)
		h.currentNetworkState()
		clk.Advance(wifi.NegationSettleWindow * 2)
		h.pruneManualOverrides(h.currentNetworkState())
	}
	_, held := h.manualLatchFor("T")
	return held
}

// A manual Off is released only by positive evidence of a different
// network (review N-1); missing information and same-LAN uplink changes keep
// it. Probe shapes follow each platform's DefaultRoute/GatewayMAC.
func TestManualOffReleaseNeedsPositiveNetworkChange(t *testing.T) {
	home := netProbeResult{Gateway: "192.168.1.1", Iface: "en0", GatewayMAC: "aa:aa:aa:aa:aa:01", Subnets: []string{"192.168.1.0/24"}, PrimaryIsWiFi: true}
	eth := home // docked: same LAN over Ethernet
	eth.Iface, eth.PrimaryIsWiFi = "en7", false
	newRouter := home
	newRouter.GatewayMAC = "bb:bb:bb:bb:bb:02"
	noARP := home
	noARP.GatewayMAC = ""
	renew := home
	renew.Subnets = []string{"192.168.1.0/24", "2001:db8:9::/64"}
	offline := netProbeResult{PrimaryIsWiFi: true}
	// Another VPN owns the default route: macOS blanks the tunnel iface and
	// reports the tunnel peer as gateway; there is no ARP entry or subnet.
	otherVPN := netProbeResult{Gateway: "10.8.0.1", PrimaryIsWiFi: true}
	otherLAN := netProbeResult{Gateway: "10.20.0.1", Iface: "en0", GatewayMAC: "ee:ee:ee:ee:ee:05", Subnets: []string{"10.20.0.0/24"}, PrimaryIsWiFi: true}
	// Different router sharing 192.168.1.0/24 and the gateway IP.
	b := netProbeResult{Gateway: "192.168.1.1", Iface: "en0", GatewayMAC: "cc:cc:cc:cc:cc:03", Subnets: []string{"192.168.1.0/24"}, PrimaryIsWiFi: true}
	// Windows: iface never resolved, IsWiFiInterface always true.
	win := netProbeResult{Gateway: "10.0.0.1", GatewayMAC: "aa:aa:aa:aa:aa:01", PrimaryIsWiFi: true}
	win2 := netProbeResult{Gateway: "10.1.0.1", GatewayMAC: "dd:dd:dd:dd:dd:04", PrimaryIsWiFi: true}
	win2NoARP := win2
	win2NoARP.GatewayMAC = ""
	winNoARP := win
	winNoARP.GatewayMAC = ""

	for _, tc := range []struct {
		name  string
		ssid0 string
		p0    netProbeResult
		steps []latchStep
		held  bool
	}{
		{"same SSID, different router", "Home", home, []latchStep{{"Home", newRouter}}, false},
		{"different SSID and LAN", "Home", home, []latchStep{{"Cafe", otherLAN}}, false},
		{"same router, SSID hidden", "Home", home, []latchStep{{"", home}}, true},
		{"ARP miss on the same network", "Home", home, []latchStep{{"Home", noARP}}, true},
		{"DHCP renew and IPv6 prefix", "Home", home, []latchStep{{"Home", renew}}, true},
		{"Wi-Fi to Ethernet on the same LAN, SSID kept", "Home", home, []latchStep{{"Home", eth}}, true},
		{"Wi-Fi to Ethernet on the same LAN, SSID blank", "Home", home, []latchStep{{"", eth}}, true},
		{"offline then back", "Home", home, []latchStep{{"", offline}, {"Home", home}}, true},
		{"another VPN takes the default route, SSID known", "Home", home, []latchStep{{"Home", otherVPN}}, true},
		{"another VPN takes the default route, SSID unknown", "", home, []latchStep{{"", otherVPN}}, true},
		{"SSID unknown, move to another router on the same /24", "", home, []latchStep{{"", b}}, false},
		{"Windows wired, different gateway MAC", "", win, []latchStep{{"", win2}}, false},
		{"Windows wired, no ARP, different gateway IP", "", win, []latchStep{{"", win2NoARP}}, false},
		{"Windows wired, ARP miss on the same network", "", win, []latchStep{{"", winNoARP}}, true},
		{"Windows Wi-Fi to wired on the same LAN", "Home", win, []latchStep{{"", win}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := latchHeldAfter(t, tc.ssid0, tc.p0, tc.steps...); got != tc.held {
				t.Fatalf("latch held = %v, want %v", got, tc.held)
			}
		})
	}
}

// A latch made without the gateway MAC must not adopt the MAC of another
// network it later cannot tell apart; otherwise returning to the original
// network releases the user's Off there (review N-1, A->B->A).
func TestManualOffNotReleasedOnReturnAfterIndistinguishableNetwork(t *testing.T) {
	a := netProbeResult{Gateway: "192.168.1.1", Iface: "en0", Subnets: []string{"192.168.1.0/24"}, PrimaryIsWiFi: true}
	aWithARP := a
	aWithARP.GatewayMAC = "aa:aa:aa:aa:aa:01"
	b := a
	b.GatewayMAC = "cc:cc:cc:cc:cc:03"
	for _, ssid := range []string{"", "Coffee"} { // SSID unknown, or shared by both routers
		if !latchHeldAfter(t, ssid, a, latchStep{ssid, b}, latchStep{ssid, aWithARP}) {
			t.Fatalf("ssid %q: Off released on returning to the network it was made on", ssid)
		}
	}
	// A known MAC at latch time still detects the other router.
	if latchHeldAfter(t, "Coffee", aWithARP, latchStep{"Coffee", b}) {
		t.Fatal("same SSID with a different gateway MAC no longer releases")
	}
}

// A latch made while the network was unknown (blank SSID on Wi-Fi) still
// adopts the first settled, known network as its baseline.
func TestUnknownLatchAdoptsFirstKnownNetwork(t *testing.T) {
	roaming := netProbeResult{Gateway: "192.168.1.1", Iface: "en0", Subnets: []string{"192.168.1.0/24"}, PrimaryIsWiFi: true}
	home := roaming
	home.GatewayMAC = "aa:aa:aa:aa:aa:01"
	newRouter := home
	newRouter.GatewayMAC = "bb:bb:bb:bb:bb:02"
	if !latchHeldAfter(t, "", roaming, latchStep{"Home", home}) {
		t.Fatal("unknown latch released on its first known network")
	}
	if latchHeldAfter(t, "", roaming, latchStep{"Home", home}, latchStep{"Home", newRouter}) {
		t.Fatal("adopted baseline did not detect a different router")
	}
}
