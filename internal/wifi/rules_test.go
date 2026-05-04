package wifi

import "testing"

func TestActionTrustedSSID(t *testing.T) {
	rules := &Rules{
		Enabled:      true,
		TrustedSSIDs: []string{"HomeWiFi", "Office"},
	}
	action, _ := rules.Action("HomeWiFi")
	if action != "disconnect" {
		t.Errorf("expected disconnect for trusted SSID, got %s", action)
	}
}

func TestActionPerTunnelMatch(t *testing.T) {
	rules := &Rules{
		Enabled: true,
		PerTunnel: map[string]TunnelSSIDs{
			"vpn-secure": {AutoConnectSSIDs: []string{"CafeWiFi", "Airport"}},
		},
	}
	action, tunnel := rules.Action("CafeWiFi")
	if action != "connect" || tunnel != "vpn-secure" {
		t.Errorf("expected connect/vpn-secure, got %s/%s", action, tunnel)
	}
}

func TestActionMultiTunnelDeterministic(t *testing.T) {
	// When two tunnels claim the same SSID, the lexicographically
	// first wins. Repeating Action() must always return the same
	// tunnel — Go map iteration order is randomized, so we exercise
	// the sort path.
	rules := &Rules{
		Enabled: true,
		PerTunnel: map[string]TunnelSSIDs{
			"zebra-vpn":  {AutoConnectSSIDs: []string{"Shared"}},
			"alpha-vpn":  {AutoConnectSSIDs: []string{"Shared"}},
			"middle-vpn": {AutoConnectSSIDs: []string{"Shared"}},
		},
	}
	for i := 0; i < 50; i++ {
		_, tunnel := rules.Action("Shared")
		if tunnel != "alpha-vpn" {
			t.Fatalf("iteration %d: expected alpha-vpn, got %s", i, tunnel)
		}
	}
}

func TestActionTrustedOverridesPerTunnel(t *testing.T) {
	// A trusted SSID disconnects even when a tunnel rule would also
	// match — trust is the higher-priority signal.
	rules := &Rules{
		Enabled:      true,
		TrustedSSIDs: []string{"home"},
		PerTunnel: map[string]TunnelSSIDs{
			"work-vpn": {AutoConnectSSIDs: []string{"home"}},
		},
	}
	action, _ := rules.Action("home")
	if action != "disconnect" {
		t.Errorf("expected disconnect, got %s", action)
	}
}

func TestActionDisabled(t *testing.T) {
	rules := &Rules{
		Enabled: false,
		PerTunnel: map[string]TunnelSSIDs{
			"vpn": {AutoConnectSSIDs: []string{"AnySSID"}},
		},
	}
	action, _ := rules.Action("AnySSID")
	if action != "none" {
		t.Errorf("expected none when disabled, got %s", action)
	}
}

func TestActionEmptySSID(t *testing.T) {
	rules := &Rules{Enabled: true}
	action, _ := rules.Action("")
	if action != "none" {
		t.Errorf("expected none for empty SSID, got %s", action)
	}
}

func TestActionNoMatch(t *testing.T) {
	rules := &Rules{
		Enabled: true,
		PerTunnel: map[string]TunnelSSIDs{
			"vpn": {AutoConnectSSIDs: []string{"OfficeWiFi"}},
		},
	}
	action, _ := rules.Action("RandomWiFi")
	if action != "none" {
		t.Errorf("expected none, got %s", action)
	}
}
