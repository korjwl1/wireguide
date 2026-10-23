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
// so macOS instead coordinates endpoint-route changes with its outer
// send gate and verifies the kernel's forwarding decision.
func pinSocketToPhysical(_ conn.Bind, _ string) (uint32, uint32, error) {
	return 0, 0, nil
}

// startSocketBindMonitor is a no-op on non-Windows platforms.
func startSocketBindMonitor(_ context.Context, _ conn.Bind, _ string, _, _ uint32) {
}
