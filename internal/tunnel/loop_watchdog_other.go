//go:build !windows && !darwin

package tunnel

import "context"

// startLoopWatchdog is a no-op on platforms where the kernel makes the
// routing-loop class physically impossible at the socket layer:
//
//   - Linux: wireguard-go's conn/mark_unix.go calls setsockopt(SO_MARK)
//     on its UDP sockets, and Linux fwmark + `ip rule` policy routing
//     means encrypted WG datagrams can't re-enter the tunnel device.
//     No defense-in-depth needed.
//
// Windows and macOS each ship a real implementation in
// loop_watchdog_{windows,darwin}.go.
func startLoopWatchdog(_ context.Context, _ string, _ func(bytesPerSec uint64)) {}
