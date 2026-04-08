//go:build windows

package helper

// isDaemon returns false on Windows. The helper is always spawned via UAC
// elevation (not a persistent Windows service), so it should always use the
// shutdown grace timer to avoid orphan processes.
func isDaemon() bool {
	return false
}
