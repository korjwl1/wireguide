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
