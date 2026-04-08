//go:build linux

package helper

// isDaemon returns false on Linux. The helper is always spawned via pkexec
// (not a persistent system service), so it should always use the shutdown
// grace timer to avoid orphan processes. On Linux, PPID==1 simply means the
// parent exited and the process was reparented to systemd/init — this does
// NOT indicate a daemon lifecycle like macOS LaunchDaemon.
func isDaemon() bool {
	return false
}
