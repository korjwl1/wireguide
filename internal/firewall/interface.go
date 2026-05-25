// Package firewall provides OS-specific kill switch and DNS leak protection.
package firewall

// FirewallManager controls kill switch and DNS leak protection.
type FirewallManager interface {
	// EnableKillSwitch blocks all traffic except through the WireGuard tunnel.
	// interfaceName: WG interface (e.g., "utun4"). May be EMPTY when the user
	//   toggles the kill switch on without an active tunnel — implementations
	//   should install the "block everything not specifically allowed" base
	//   filter set (loopback / DHCP / NDP) so the firewall is in effect
	//   immediately. Tunnel-specific permits are then added by
	//   AddKillSwitchTunnel when a tunnel actually connects.
	// ifaceAddresses: WG interface addresses (CIDR, e.g. "10.0.0.2/24") — used on
	//   Linux to build anti-spoof (preraw) nftables chains. Ignored when
	//   interfaceName is empty.
	// endpoints: pre-resolved WG server endpoints as "ip:port" pairs — must be
	//   allowed through. Callers must resolve hostnames BEFORE the tunnel routes
	//   are installed, otherwise DNS resolution would go through the tunnel and
	//   may fail. If port is unknown or not applicable, use "ip:" (empty port).
	//   Empty/nil when interfaceName is empty.
	EnableKillSwitch(interfaceName string, ifaceAddresses []string, endpoints []string) error

	// AddKillSwitchTunnel installs the per-tunnel permit filters (Permit
	// tunnel LUID + Permit each peer endpoint outbound). Called when a tunnel
	// connects WHILE the kill switch is already enabled. No-op if the kill
	// switch is off. Idempotent for the same tunnel name.
	AddKillSwitchTunnel(interfaceName string, endpoints []string) error

	// RemoveKillSwitchTunnel removes the per-tunnel permits that
	// AddKillSwitchTunnel installed. Called when a tunnel disconnects. The
	// base kill-switch filters stay in place, so traffic remains blocked
	// until the user explicitly toggles the kill switch off.
	RemoveKillSwitchTunnel(interfaceName string) error

	// DisableKillSwitch removes ALL kill switch firewall rules (base +
	// any per-tunnel filters added since enable).
	DisableKillSwitch() error

	// EnableEndpointProtection installs always-on routing-loop protection
	// for a full-tunnel connect, independently of the kill switch. The
	// canonical Windows implementation blocks UDP outbound to each peer
	// endpoint when the packet would leave via the tunnel adapter itself
	// — so a missing or stale bypass /32 route can no longer recurse
	// encrypted handshake traffic into the tunnel. Defense in depth on top
	// of the bypass host route, intentionally narrow (UDP + exact remote
	// IP+port + tunnel LUID) so it never interferes with normal user
	// traffic on the tunnel.
	//
	// Caller passes "ip:port" pairs (the same form ResolvedEndpoints
	// returns). No-op + nil return on non-Windows: macOS and Linux have
	// fwmark / interface-binding alternatives that wireguard-go already
	// uses, so the loop class doesn't surface there.
	EnableEndpointProtection(tunnelInterfaceName string, endpoints []string) error

	// DisableEndpointProtection removes the filters installed by
	// EnableEndpointProtection for one tunnel. Idempotent — no-op if no
	// filters are tracked for that tunnel name (e.g. split tunnel never
	// called Enable).
	DisableEndpointProtection(tunnelInterfaceName string) error

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

	// RecoverFromCrash restores firewall state persisted by a previous helper
	// instance that crashed. Returns true when recovery actually ran (e.g. a
	// pf state file was found on macOS). Safe to call when no prior crash
	// state exists. Called once during helper startup, before any tunnel
	// brings new rules up.
	RecoverFromCrash() bool
}
