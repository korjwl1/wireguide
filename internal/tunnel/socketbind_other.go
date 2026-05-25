//go:build !windows

package tunnel

import (
	"context"

	"golang.zx2c4.com/wireguard/conn"
)

// pinSocketToPhysical is a no-op on non-Windows platforms.
//
// On Linux the kernel handles loop protection via SO_MARK + policy
// routing (wg-quick semantics); wireguard-go's conn/mark_unix.go
// installs the mark on socket creation. On macOS/BSD the bind doesn't
// implement BindSocketToInterface (conn/mark_default.go is a no-op),
// and the /32 bypass route in DarwinManager.AddRoutes is the only
// safety net we ship there — the equivalent socket-binding work
// would need a fresh implementation (likely IP_BOUND_IF via setsockopt
// on the underlying *net.UDPConn fd), tracked as future work.
func pinSocketToPhysical(_ conn.Bind, _ string) (uint32, uint32) {
	return 0, 0
}

// startSocketBindMonitor is a no-op on non-Windows platforms.
func startSocketBindMonitor(_ context.Context, _ conn.Bind, _ string, _, _ uint32) {
}
