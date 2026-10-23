package wifi

import (
	"net"
	"strings"
)

// Pure parsers shared by the per-OS DefaultRoute / IsWiFiInterface
// implementations, kept untagged so their tests run everywhere.

// parseRouteGetDefault extracts the gateway IP and interface from the
// output of macOS `route -n get default`. Either may be "".
func parseRouteGetDefault(out string) (gw, iface string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "gateway:"):
			v := strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
			if net.ParseIP(v) != nil {
				gw = v
			}
		case strings.HasPrefix(line, "interface:"):
			iface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	return gw, iface
}

// parseWiFiHardwarePorts returns the BSD device names (e.g. "en0") of the
// Wi-Fi ports in `networksetup -listallhardwareports` output.
func parseWiFiHardwarePorts(out string) map[string]bool {
	devs := map[string]bool{}
	isWiFi := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Hardware Port:"):
			port := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "Hardware Port:")))
			isWiFi = port == "wi-fi" || port == "airport"
		case strings.HasPrefix(line, "Device:"):
			if isWiFi {
				if d := strings.TrimSpace(strings.TrimPrefix(line, "Device:")); d != "" {
					devs[d] = true
				}
			}
			isWiFi = false
		}
	}
	return devs
}
