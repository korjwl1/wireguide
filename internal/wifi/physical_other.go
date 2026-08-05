//go:build !linux

package wifi

// isVirtualIface is Linux-only sysfs knowledge; macOS and Windows rely on
// the name-based isTunnelIface filter alone. On macOS the tunnel/virtual
// namespace is well-conventioned (utun*, bridge*, awdl* — the latter two
// are excluded by the link-local check on their addresses), and Windows
// virtual adapters are caught by the explicit wireguard/wintun match.
func isVirtualIface(string) bool { return false }
