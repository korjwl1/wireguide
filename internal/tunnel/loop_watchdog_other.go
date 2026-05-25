//go:build !windows

package tunnel

import "context"

// startLoopWatchdog is a no-op on non-Windows platforms.
//
//   - Linux: wireguard-go's conn/mark_unix.go calls setsockopt(SO_MARK)
//     on its UDP sockets, and DarwinManager's wg-quick-style fwmark +
//     `ip rule` policy routing makes the loop physically impossible at
//     the socket layer. No defense-in-depth needed.
//   - macOS: the loop class IS theoretically possible (no SO_MARK and
//     no IP_BOUND_IF — conn/mark_default.go is a no-op SetMark on
//     Darwin) but is mitigated by DarwinManager.AddRoutes installing
//     /32 bypass host routes BEFORE the /1 split routes, with fail-fast
//     gateway-detection. A SIOCGIFDATA-based watchdog mirroring the
//     Windows GetIfEntry2 path is tracked as a follow-up if the
//     residual risk shows up in the wild.
func startLoopWatchdog(_ context.Context, _ string, _ func(bytesPerSec uint64)) {}
