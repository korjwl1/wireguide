//go:build windows

package tunnel

import "time"

// getStatusForEngine on Windows uses the in-memory UAPI path (see
// GetStatusFromEngine doc) because wgctrl can't open wireguard-go's
// real named pipe — it's anchored at
// \\.\pipe\ProtectedPrefix\Administrators\WireGuard\<iface>, which
// rejects every owner SID except Administrators-group or SYSTEM, and
// our helper runs as the elevated user (not the group).
//
// The in-memory path routes status reads through wireguard-go's own
// IpcHandle loop over a net.Pipe rather than calling the documented-
// but-fragile wgDevice.IpcGet() directly. A previous attempt to call
// IpcGet() from the eventLoop goroutine killed the helper within
// ~450ms of `tunnel connected` with no recoverable trace.
func getStatusForEngine(engine *Engine, tunnelName string, connectedAt time.Time) (*ConnectionStatus, error) {
	return GetStatusFromEngine(engine, tunnelName, connectedAt)
}
