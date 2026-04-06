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
	//
	// endpointIPs carries every peer endpoint's ALREADY-RESOLVED IP
	// literal (not hostnames!) — the caller must have resolved these
	// before calling AddRoutes, because by this point any DNS lookup we
	// do ourselves would get routed through the partially-installed
	// tunnel and deadlock. Multi-peer configs should pass all resolved
	// IPs for all peers. Pass an empty slice to disable bypass setup.
	AddRoutes(ifaceName string, allowedIPs []string, fullTunnel bool, endpointIPs []string, tableCfg string, fwmarkCfg string) error

	// RemoveRoutes removes routes that were added by AddRoutes.
	RemoveRoutes(ifaceName string, allowedIPs []string, fullTunnel bool) error

	// SetDNS configures DNS servers for the tunnel.
	SetDNS(ifaceName string, servers []string) error

	// RestoreDNS restores DNS configuration to pre-tunnel state. Relies on
	// the in-memory "saved" snapshot taken when SetDNS was called — only
	// meaningful on the same process instance that called SetDNS.
	RestoreDNS(ifaceName string) error

	// ResetDNSToSystemDefault clears any DNS overrides we may have installed
	// back to the system default (DHCP-provided). Unlike RestoreDNS this
	// does NOT rely on in-memory state — it's designed for crash recovery
	// on a fresh process that has no memory of the pre-crash configuration.
	// Best-effort: errors are logged, not returned.
	ResetDNSToSystemDefault() error

	// Cleanup removes the interface and all associated configuration.
	Cleanup(ifaceName string) error
}

// DNSStateRestorer is an optional interface that allows restoring DNS
// settings from a persisted pre-modification snapshot during crash recovery.
// Unlike RestoreDNS (which needs in-memory state from the same process),
// this uses the snapshot saved to disk, preserving custom user preferences.
type DNSStateRestorer interface {
	RestoreDNSFromSnapshot(preModDNS map[string][]string) error
}

// SavedDNSSnapshot returns the current in-memory DNS snapshot for
// persistence to the crash recovery journal. Platform managers that
// capture per-service DNS state should implement this.
type DNSSnapshotProvider interface {
	SavedDNSSnapshot() map[string][]string
}

// RoutingStateRestorer is an optional interface that platform managers may
// implement to accept persisted table/fwmark values during crash recovery.
// This allows cleanup to use the correct routing table instead of hardcoded
// defaults when the process has no in-memory state.
type RoutingStateRestorer interface {
	RestoreRoutingState(table, fwmark string)
}

// OriginalNetworkState captures the pre-tunnel network state for restoration.
type OriginalNetworkState struct {
	DNSServers []string `json:"dns_servers"`
	DefaultGW  string   `json:"default_gateway"`
	DefaultIf  string   `json:"default_interface"`
}
