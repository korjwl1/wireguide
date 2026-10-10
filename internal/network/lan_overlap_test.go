package network

import (
	"net"
	"testing"
)

func withLocalAddrs(t *testing.T, addrs ...string) {
	t.Helper()
	orig := LocalPhysicalAddrs
	t.Cleanup(func() { LocalPhysicalAddrs = orig })
	LocalPhysicalAddrs = func() []*net.IPNet {
		var out []*net.IPNet
		for _, a := range addrs {
			ip, n, err := net.ParseCIDR(a)
			if err != nil {
				t.Fatalf("bad test addr %q: %v", a, err)
			}
			out = append(out, &net.IPNet{IP: ip, Mask: n.Mask})
		}
		return out
	}
}

func TestLocalNetworkOverlap(t *testing.T) {
	withLocalAddrs(t, "192.168.50.65/24", "fd00:1::5/64", "10.0.0.5/24", "2001:db8::5/64")
	cases := []struct {
		cidr string
		want bool
	}{
		{"192.168.50.0/24", true},
		{"192.168.50.65/32", true},
		{"192.168.1.0/24", false},
		{"192.168.0.0/16", false}, // broader than the on-link /24: connected route still wins
		{"10.0.0.0/8", false},
		{"10.0.0.0/24", true},
		{"10.0.0.5/32", true},
		{"2000::/3", false},
		{"2001:db8::/64", true},
		{"2001:db8::/48", false},
		{"fd00:1::/64", true},
		{"fd00:2::/64", false},
		{"0.0.0.0/0", false},   // full tunnel is never an overlap
		{"128.0.0.0/1", false}, // split default
		{"garbage", false},
	}
	for _, tc := range cases {
		if _, got := LocalNetworkOverlap(tc.cidr); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.cidr, got, tc.want)
		}
	}
	cidr, ip, ok := FirstLocalNetworkOverlap([]string{"192.168.1.0/24", "192.168.50.0/24"})
	if !ok || cidr != "192.168.50.0/24" || ip.String() != "192.168.50.65" {
		t.Errorf("first overlap: %q %v %v", cidr, ip, ok)
	}
}

func TestIsNonPhysicalIfaceName(t *testing.T) {
	for _, n := range []string{"utun4", "lo0", "gif0", "stf0", "awdl0", "llw0", "anpi0", "bridge100", "vmenet0", "ap1", "wg0", "WireGuide", "vnic0", "vmnet8", "vboxnet0", "docker0", "br-1a2b", "veth12", "virbr0", "vEthernet (WSL)"} {
		if !isNonPhysicalIfaceName(n) {
			t.Errorf("%s should be non-physical", n)
		}
	}
	for _, n := range []string{"en0", "en5", "eth0", "wlan0", "Ethernet"} {
		if isNonPhysicalIfaceName(n) {
			t.Errorf("%s should be physical", n)
		}
	}
}
