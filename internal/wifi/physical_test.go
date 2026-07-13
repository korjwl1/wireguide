package wifi

import "testing"

func TestIsTunnelIface(t *testing.T) {
	tunnels := []string{"utun0", "utun7", "wg0", "tun1", "tap0", "WireGuide", "wireguard1", "ppp0", "ipsec0"}
	for _, n := range tunnels {
		if !isTunnelIface(n) {
			t.Errorf("%q should be detected as a tunnel interface", n)
		}
	}
	physical := []string{"en0", "en1", "eth0", "wlan0", "Ethernet", "Wi-Fi", "Local Area Connection"}
	for _, n := range physical {
		if isTunnelIface(n) {
			t.Errorf("%q should NOT be detected as a tunnel interface", n)
		}
	}
}

func TestPhysicalInterfaceIPs_NoLinkLocalOrLoopback(t *testing.T) {
	// Can't assert specific addresses on an arbitrary CI host, but the
	// result must never contain loopback or link-local addresses.
	for _, ip := range PhysicalInterfaceIPs() {
		if ip.IsLoopback() {
			t.Errorf("loopback leaked into physical IPs: %s", ip)
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			t.Errorf("link-local leaked into physical IPs: %s", ip)
		}
	}
}
