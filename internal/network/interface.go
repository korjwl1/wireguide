// Package network provides OS-specific IP, routing, and DNS configuration.
package network

// NetworkManager handles OS-level network configuration for WireGuard tunnels.
type NetworkManager interface {
	// AssignAddress assigns an IP address to the named interface.
	AssignAddress(ifaceName string, addresses []string) error

	// SetMTU sets the MTU on the named interface.
	SetMTU(ifaceName string, mtu int) error

	// BringUp brings the interface up.
	BringUp(ifaceName string) error

	// AddRoutes adds routes for the given CIDRs via the named interface.
	// If fullTunnel is true, uses OS-specific full-tunnel routing strategy.
	AddRoutes(ifaceName string, allowedIPs []string, fullTunnel bool, endpoint string) error

	// RemoveRoutes removes routes that were added by AddRoutes.
	RemoveRoutes(ifaceName string, allowedIPs []string, fullTunnel bool) error

	// SetDNS configures DNS servers for the tunnel.
	SetDNS(ifaceName string, servers []string) error

	// RestoreDNS restores DNS configuration to pre-tunnel state.
	RestoreDNS(ifaceName string) error

	// Cleanup removes the interface and all associated configuration.
	Cleanup(ifaceName string) error
}

// OriginalNetworkState captures the pre-tunnel network state for restoration.
type OriginalNetworkState struct {
	DNSServers  []string `json:"dns_servers"`
	DefaultGW   string   `json:"default_gateway"`
	DefaultIf   string   `json:"default_interface"`
}
