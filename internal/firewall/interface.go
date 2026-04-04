// Package firewall provides OS-specific kill switch and DNS leak protection.
package firewall

// FirewallManager controls kill switch and DNS leak protection.
type FirewallManager interface {
	// EnableKillSwitch blocks all traffic except through the WireGuard tunnel.
	// interfaceName: WG interface (e.g., "utun4")
	// endpoint: WG server endpoint (host:port) — must be allowed through
	EnableKillSwitch(interfaceName string, endpoint string) error

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
