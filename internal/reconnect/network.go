package reconnect

// NetworkChangeDetector watches for network reachability transitions
// (Wi-Fi off/on, Ethernet plug/unplug, Wi-Fi ↔ Ethernet handover) and
// fires on its channel each time the system becomes reachable on a
// new path. On macOS this maps to SCNetworkReachability callbacks via
// SystemConfiguration.framework. Non-macOS platforms get a no-op
// detector that never fires (existing route-monitor logic in
// internal/network/* covers their reconnection needs adequately for
// today's scope).
type NetworkChangeDetector interface {
	Start()
	Stop()
	ChangeChan() <-chan struct{}
}

// OnlineReporter is optionally implemented by a NetworkChangeDetector that
// knows whether the machine currently has a primary network interface. A
// detector without it (or no detector) is treated as always online.
type OnlineReporter interface {
	Online() bool
}

// onlineFromPrimaries reports whether the machine has a primary network
// interface, given the IPv4 primary (already read successfully) and the IPv6
// primary. An IPv6-only network has no IPv4 key, so either family counts. If
// the IPv6 read failed the answer is unknown and counts as online: a health
// check that runs spuriously is harmless, one that never runs is not.
func onlineFromPrimaries(iface4, iface6 string, ok6 bool) bool {
	return iface4 != "" || iface6 != "" || !ok6
}
