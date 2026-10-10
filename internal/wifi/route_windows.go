//go:build windows

package wifi

import "github.com/korjwl1/wireguide/internal/network"

// DefaultRoute returns the physical IPv4 default gateway. The interface
// name is not resolved on Windows ("" = unknown), which keeps an empty SSID
// in the hold state for negated SSID rules.
func DefaultRoute() (gateway, iface string) {
	return network.UnderlayDefaultGatewayV4(network.VPNAdapterAliases), ""
}

// IsWiFiInterface is unknown on Windows; answering true makes an empty SSID
// hold rather than count as "no SSID".
func IsWiFiInterface(string) bool { return true }
