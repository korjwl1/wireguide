//go:build darwin

package wifi

import (
	"context"
	"os/exec"
	"sync"
	"time"
)

// Seams for tests.
var (
	routeGetDefaultOutput = func() (string, error) {
		return runLocaleC("route", "-n", "get", "default")
	}
	hardwarePortsOutput = func() (string, error) {
		return runLocaleC("networksetup", "-listallhardwareports")
	}
	routeNow = time.Now
)

func runLocaleC(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.Output()
	return string(out), err
}

// DefaultRoute returns the IPv4 default route's gateway and interface.
// iface is "" when unknown, and also when the default route currently
// points at a tunnel (a VPN that replaced the default route), so callers
// never mistake a tunnel for the physical uplink.
func DefaultRoute() (gateway, iface string) {
	out, err := routeGetDefaultOutput()
	if err != nil {
		return "", ""
	}
	gateway, iface = parseRouteGetDefault(out)
	if isTunnelIface(iface) {
		iface = ""
	}
	return gateway, iface
}

const wifiDeviceCacheTTL = 60 * time.Second

var wifiDevCache struct {
	mu      sync.Mutex
	devs    map[string]bool
	ok      bool
	fetched time.Time
}

// IsWiFiInterface reports whether iface is a Wi-Fi device, from
// `networksetup -listallhardwareports` (cached ~60 s). If the listing
// fails it answers true (unknown is treated as Wi-Fi, so an empty SSID
// holds rather than being read as "no SSID").
func IsWiFiInterface(iface string) bool {
	wifiDevCache.mu.Lock()
	defer wifiDevCache.mu.Unlock()
	now := routeNow()
	if !wifiDevCache.ok || now.Sub(wifiDevCache.fetched) > wifiDeviceCacheTTL {
		out, err := hardwarePortsOutput()
		if err != nil || out == "" {
			return true
		}
		wifiDevCache.devs = parseWiFiHardwarePorts(out)
		wifiDevCache.ok = true
		wifiDevCache.fetched = now
	}
	return wifiDevCache.devs[iface]
}
