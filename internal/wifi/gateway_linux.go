//go:build linux

package wifi

import (
	"os"
	"strings"
)

// GatewayMAC returns the lower-cased MAC of the IPv4 default gateway,
// read straight from /proc (no exec, locale-independent). "" when
// unavailable. Route selection honours flags/metric/netmask and skips
// tunnel and virtual interfaces; the ARP lookup is scoped to the route's
// device and requires a completed entry (issue #22).
func GatewayMAC() string {
	routeTable, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	gw, iface := bestDefaultRoute(routeTable, func(name string) bool {
		return isTunnelIface(name) || isVirtualIface(name)
	})
	if gw == "" {
		return ""
	}
	arpTable, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return ""
	}
	return arpMACForIPOnIface(arpTable, gw, iface)
}

// isVirtualIface reports whether the named interface has no backing
// hardware device. /sys/class/net/<if>/device is a symlink to the
// PCI/USB/SDIO device and is absent for every bridge, veth, tun/tap,
// bond and WireGuard interface — a single check that catches docker0,
// virbr0, tailscale0, vmnet*, CNI bridges and the rest of the
// name-denylist's blind spots. The tun_flags probe additionally catches
// tun/tap devices, mirroring internal/reconnect's isTunnel.
func isVirtualIface(name string) bool {
	if name == "" || strings.ContainsAny(name, "/\\") {
		return true
	}
	if _, err := os.Stat("/sys/class/net/" + name + "/tun_flags"); err == nil {
		return true
	}
	if _, err := os.Stat("/sys/class/net/" + name + "/device"); err == nil {
		return false
	}
	return true
}
