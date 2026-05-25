//go:build !windows

package tunnel

import "context"

// startLoopWatchdog is a no-op on non-Windows platforms — the routing
// loop class this guards against is specific to userspace wireguard-go
// on Windows (no fwmark on Linux; bind-by-interface on macOS).
func startLoopWatchdog(_ context.Context, _ string, _ func(bytesPerSec uint64)) {}
