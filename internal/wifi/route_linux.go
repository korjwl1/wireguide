//go:build linux

package wifi

import "os"

// DefaultRoute returns the IPv4 default route's gateway and interface
// (physical uplinks only), "" when unavailable.
func DefaultRoute() (gateway, iface string) {
	routeTable, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", ""
	}
	return bestDefaultRoute(routeTable, func(name string) bool {
		return isTunnelIface(name) || isVirtualIface(name)
	})
}

// IsWiFiInterface reports whether iface is a wireless device.
func IsWiFiInterface(iface string) bool {
	if iface == "" {
		return false
	}
	_, err := os.Stat("/sys/class/net/" + iface + "/wireless")
	return err == nil
}
