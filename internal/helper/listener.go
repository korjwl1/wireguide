package helper

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"runtime"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/launchd"
)

// activateLaunchd is launchd.Listeners, replaceable in tests.
var activateLaunchd = launchd.Listeners

// fallbackAddr is the address a non-launchd-managed helper listens on.
// ipc.Listen refuses to manage /var/run itself, so a non-launchd start
// pointed at the launchd socket path (a dev run with default arguments) keeps
// to the legacy subdirectory instead.
func fallbackAddr(addr string) string {
	if filepath.Dir(addr) == filepath.Dir(ipc.DarwinSocketPath) {
		slog.Warn("not launchd-managed; using legacy socket directory instead of /var/run",
			"requested", addr, "using", ipc.LegacyDarwinSocketPath)
		return ipc.LegacyDarwinSocketPath
	}
	return addr
}

// acquireListener returns the socket the IPC server should accept on.
//
// On darwin the LaunchDaemon plist declares the socket (Sockets.Listeners),
// so launchd owns it from boot and starts this process on the first connect;
// adopting that socket is what lets the GUI "start" the helper just by
// dialing, without an administrator prompt. ipc.Listen must NOT run in that
// case: it unlinks the path, which would orphan launchd's socket.
//
// Only "not launchd-managed" (dev run, test, old plist) falls back to
// listening ourselves. Any other activation error is fatal: continuing would
// leave launchd's connection pending and respawn the helper in a loop.
func acquireListener(addr string, ownerUID int, ownerSID string) (l net.Listener, listenAddr string, activated bool, err error) {
	if runtime.GOOS == "darwin" {
		ls, aerr := activateLaunchd()
		switch {
		case aerr == nil && len(ls) > 0:
			for _, extra := range ls[1:] {
				extra.Close()
			}
			return ls[0], addr, true, nil
		case aerr == nil, errors.Is(aerr, launchd.ErrNotManaged), errors.Is(aerr, launchd.ErrNoSocketEntry):
			slog.Info("launchd socket activation not in use; listening directly", "reason", aerr)
		default:
			return nil, addr, false, fmt.Errorf("launchd socket activation: %w", aerr)
		}
		addr = fallbackAddr(addr)
	}
	l, err = ipc.Listen(addr, ownerUID, ownerSID)
	if err != nil {
		return nil, addr, false, fmt.Errorf("listen %s: %w", addr, err)
	}
	return l, addr, false, nil
}
