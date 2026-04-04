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

func TestActionMappedSSID(t *testing.T) {
	rules := &Rules{
		Enabled:       true,
		SSIDTunnelMap: map[string]string{"CafeWiFi": "vpn-secure"},
	}
	action, tunnel := rules.Action("CafeWiFi")
	if action != "connect" || tunnel != "vpn-secure" {
		t.Errorf("expected connect/vpn-secure, got %s/%s", action, tunnel)
	}
}

func TestActionUntrustedAutoConnect(t *testing.T) {
	rules := &Rules{
		Enabled:              true,
		AutoConnectUntrusted: true,
		DefaultTunnel:        "vpn-default",
	}
	action, tunnel := rules.Action("UnknownWiFi")
	if action != "connect" || tunnel != "vpn-default" {
		t.Errorf("expected connect/vpn-default, got %s/%s", action, tunnel)
	}
}

func TestActionDisabled(t *testing.T) {
	rules := &Rules{Enabled: false}
	action, _ := rules.Action("AnySSID")
	if action != "none" {
		t.Errorf("expected none when disabled, got %s", action)
	}
}

func TestActionEmptySSID(t *testing.T) {
	rules := &Rules{Enabled: true, AutoConnectUntrusted: true, DefaultTunnel: "vpn"}
	action, _ := rules.Action("")
	if action != "none" {
		t.Errorf("expected none for empty SSID, got %s", action)
	}
}

func TestActionNoMatch(t *testing.T) {
	rules := &Rules{
		Enabled:              true,
		AutoConnectUntrusted: false,
	}
	action, _ := rules.Action("RandomWiFi")
	if action != "none" {
		t.Errorf("expected none, got %s", action)
	}
}
