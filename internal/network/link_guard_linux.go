//go:build linux

package network

// SetLinkCleanupGuard installs a guard consulted by Cleanup before the
// legacy name-based link deletion.
func (m *LinuxManager) SetLinkCleanupGuard(guard LinkCleanupGuard) {
	m.linkCleanupGuard = guard
}
