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

// DNSSnapshot carries the pre-VPN per-service DNS state needed for a
// COMPLETE restore. Search domains must ride along with servers: the
// previous servers-only snapshot meant the restore path left
// `networksetup -setsearchdomains` overrides behind forever (issue #34).
type DNSSnapshot struct {
	Servers map[string][]string `json:"servers,omitempty"`
	Search  map[string][]string `json:"search,omitempty"`
}

// Empty reports whether the snapshot holds no state at all.
func (s DNSSnapshot) Empty() bool {
	return len(s.Servers) == 0 && len(s.Search) == 0
}

// DNSStateRestorer is an optional interface that allows restoring DNS
// settings from a persisted pre-modification snapshot during crash recovery.
// Unlike RestoreDNS (which needs in-memory state from the same process),
// this uses the snapshot saved to disk, preserving custom user preferences.
type DNSStateRestorer interface {
	RestoreDNSFromSnapshot(snap DNSSnapshot) error
}

// SavedDNSSnapshot returns the current in-memory DNS snapshot for
// persistence to the crash recovery journal. Platform managers that
// capture per-service DNS state should implement this.
type DNSSnapshotProvider interface {
	SavedDNSSnapshot() DNSSnapshot
}

// RoutingStateRestorer is an optional interface that platform managers may
// implement to accept persisted table/fwmark values during crash recovery.
// This allows cleanup to use the correct routing table instead of hardcoded
// defaults when the process has no in-memory state.
type RoutingStateRestorer interface {
	RestoreRoutingState(table, fwmark string)
}

// EndpointRouteStateProvider exposes only endpoint bypass/throw routes that
// this manager actually installed. Persisting the exact owned set lets crash
// recovery remove it without flushing unrelated routes from a user-selected
// custom table.
type EndpointRouteStateProvider interface {
	InstalledEndpointRoutes() []string
}

// EndpointRouteStateRestorer restores the owned endpoint-route set from the
// crash journal before RemoveRoutes runs in a fresh helper process.
type EndpointRouteStateRestorer interface {
	RestoreEndpointRoutes(routes []string)
}

// PersistentStateDirSetter lets platform managers persist recovery data next
// to the tunnel journal. Linux uses it for the original resolv.conf snapshot;
// other platforms do not need to implement it.
type PersistentStateDirSetter interface {
	SetPersistentStateDir(dataDir string)
}

// PreCloseCleaner is an optional interface for platform managers that need
// to put the tunnel interface into a "harmless" state BEFORE the TUN
// device is destroyed. On Windows the wintun adapter persists for several
// seconds after WintunCloseAdapter returns, and during that window Windows
// still treats it as a viable interface — using its metric-1 default to
// route DNS queries through a tunnel that no longer exists. Lowering its
// metric and clearing its DNS first makes that lingering adapter benign.
type PreCloseCleaner interface {
	PreCloseAdapterCleanup(ifaceName string)
}
