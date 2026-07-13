//go:build !darwin

package network

// SubscribeNetworkChange is a no-op on platforms without a process-wide
// network-change monitor (Windows' route notification is per-tunnel and
// scoped to socket re-pinning; Linux has none yet). On these the helper
// falls back to a slow poll for subnet-rule re-evaluation. SSID-based
// rules still fire instantly via the Wi-Fi monitor.
func SubscribeNetworkChange(key string, cb func()) {}

// UnsubscribeNetworkChange is the matching no-op.
func UnsubscribeNetworkChange(key string) {}
