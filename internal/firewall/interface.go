// Package firewall provides OS-specific kill switch and DNS leak protection.
package firewall

// FirewallManager controls kill switch and DNS leak protection.
type FirewallManager interface {
	// EnableKillSwitch blocks all traffic except through the WireGuard tunnel.
	// interfaceName: WG interface (e.g., "utun4")
	// ifaceAddresses: WG interface addresses (CIDR, e.g. "10.0.0.2/24") — used on
	//   Linux to build anti-spoof (preraw) nftables chains.
	// endpoints: pre-resolved WG server endpoints as "ip:port" pairs — must be
	//   allowed through. Callers must resolve hostnames BEFORE the tunnel routes
	//   are installed, otherwise DNS resolution would go through the tunnel and
	//   may fail. If port is unknown or not applicable, use "ip:" (empty port).
	EnableKillSwitch(interfaceName string, ifaceAddresses []string, endpoints []string) error

	// DisableKillSwitch removes all kill switch firewall rules.
	DisableKillSwitch() error

	// EnableDNSProtection blocks DNS (port 53) except to specified servers via WG tunnel.
	EnableDNSProtection(interfaceName string, dnsServers []string) error

	// DisableDNSProtection removes DNS protection rules.
	DisableDNSProtection() error

	// IsKillSwitchEnabled returns the current kill switch state.
	IsKillSwitchEnabled() bool

	// IsDNSProtectionEnabled returns the current DNS protection state.
	IsDNSProtectionEnabled() bool

	// Cleanup removes all firewall rules (called on shutdown/crash recovery).
	Cleanup() error
}
