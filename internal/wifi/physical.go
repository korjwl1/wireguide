package wifi

import (
	"net"
	"strings"
)

// tunnelIfacePrefixes are interface-name prefixes that belong to VPN /
// tunnel adapters, not physical uplinks. Subnet conditions must ignore
// these — a rule like "disconnect on 10.0.0.0/24" should test the real
// network the machine is on, not an address the tunnel itself assigned.
var tunnelIfacePrefixes = []string{"utun", "wg", "tun", "tap", "ipsec", "ppp"}

// PhysicalInterfaceIPs returns the unicast IP addresses currently
// assigned to physical (non-tunnel, up, non-loopback) interfaces. Used
// to evaluate subnet-based Automation conditions. Cross-platform via the
// standard net package — no per-OS code needed.
func PhysicalInterfaceIPs() []net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isTunnelIface(ifi.Name) {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			out = append(out, ip)
		}
	}
	return out
}

// isTunnelIface reports whether name looks like a VPN/tunnel adapter.
// The Windows WireGuard adapter is named "WireGuide" (or a wintun alias)
// which the wg/tun prefixes below don't catch, so match it explicitly.
func isTunnelIface(name string) bool {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "wireguide") || strings.Contains(lower, "wireguard") {
		return true
	}
	for _, p := range tunnelIfacePrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}
