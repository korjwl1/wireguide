package wifi

import "testing"

// /proc/net/route fixture columns:
// Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
const routeFixture = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
	// wg0 default route, metric 0 — must be excluded (tunnel)
	"wg0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n" +
	// eth1 default route, DOWN (flags lack RTF_UP) — must be excluded
	"eth1\t00000000\t0100A8C0\t0002\t0\t0\t50\t00000000\t0\t0\t0\n" +
	// eth0 default route, metric 100, gateway 192.168.1.1 (little-endian hex)
	"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
	// wlan0 default route, metric 600, gateway 192.168.1.1
	"wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
	// eth0 non-default route (mask not /0) — must be ignored
	"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"

func TestBestDefaultRoutePicksLowestMetricRealIface(t *testing.T) {
	isTunnel := func(name string) bool { return name == "wg0" }
	gw, iface := bestDefaultRoute([]byte(routeFixture), isTunnel)
	if gw != "192.168.1.1" {
		t.Errorf("gw: got %q, want 192.168.1.1", gw)
	}
	if iface != "eth0" {
		t.Errorf("iface: got %q, want eth0 (metric 100 beats wlan0's 600)", iface)
	}
}

func TestBestDefaultRouteAllFiltered(t *testing.T) {
	gw, iface := bestDefaultRoute([]byte(routeFixture), func(string) bool { return true })
	if gw != "" || iface != "" {
		t.Errorf("got (%q,%q), want empty when every iface is a tunnel", gw, iface)
	}
}

// /proc/net/arp fixture columns:
// IPaddress HWtype Flags HWaddress Mask Device
const arpFixture = "IP address       HW type     Flags       HW address            Mask     Device\n" +
	// same gateway IP known via docker0 — wrong device, must be skipped
	"192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:99     *        docker0\n" +
	// incomplete entry on the right device — must be skipped (no ATF_COM)
	"192.168.1.1      0x1         0x0         00:00:00:00:00:00     *        eth0\n" +
	// completed entry on the right device
	"192.168.1.1      0x1         0x2         B0:38:6C:54:8B:AB     *        eth0\n"

func TestArpMACForIPOnIface(t *testing.T) {
	got := arpMACForIPOnIface([]byte(arpFixture), "192.168.1.1", "eth0")
	if got != "b0:38:6c:54:8b:ab" {
		t.Errorf("got %q, want b0:38:6c:54:8b:ab (normalised, right device, completed)", got)
	}
}

func TestArpMACForIPOnIfaceWrongDevice(t *testing.T) {
	if got := arpMACForIPOnIface([]byte(arpFixture), "192.168.1.1", "wlan0"); got != "" {
		t.Errorf("got %q, want empty for a device with no entry", got)
	}
}

func TestArpMACIncompleteOnly(t *testing.T) {
	incomplete := "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"10.0.0.1         0x1         0x0         aa:bb:cc:dd:ee:ff     *        eth0\n"
	if got := arpMACForIPOnIface([]byte(incomplete), "10.0.0.1", "eth0"); got != "" {
		t.Errorf("got %q, want empty for an incomplete (non-ATF_COM) entry", got)
	}
}
