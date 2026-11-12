// Package launchd adopts sockets that launchd bound on the helper's behalf
// (socket activation). It is a separate package so internal/ipc stays
// cgo-free for Linux and Windows builds.
package launchd

import (
	"errors"
	"fmt"
	"syscall"
)

// AppBundleID is the app's CFBundleIdentifier (build/darwin/Info.plist). Both
// generated launchd plists list it under AssociatedBundleIdentifiers so
// System Settings > Login Items & Extensions attributes the background items
// to WireGuide instead of to an unidentified developer.
const AppBundleID = "com.korjwl1.wireguide"

// SocketName is the key under the plist's Sockets dictionary.
const SocketName = "Listeners"

var (
	// ErrNotManaged means the process was not started by launchd (dev run,
	// test, or a build without cgo). Callers fall back to listening
	// themselves.
	ErrNotManaged = errors.New("launchd: process is not managed by launchd")
	// ErrNoSocketEntry means launchd manages the process but its plist has no
	// Sockets entry named "Listeners" (an old plist). Callers fall back to
	// listening themselves.
	ErrNoSocketEntry = errors.New("launchd: no Listeners socket entry in the job's plist")
)

// mapActivateError converts launch_activate_socket's errno-style return code
// into this package's errors. ESRCH and ENOENT are the two "not activated"
// outcomes the caller may recover from; anything else is a real failure.
func mapActivateError(rc int) error {
	switch syscall.Errno(rc) {
	case 0:
		return nil
	case syscall.ESRCH:
		return ErrNotManaged
	case syscall.ENOENT:
		return ErrNoSocketEntry
	default:
		return fmt.Errorf("launchd: launch_activate_socket: %w", syscall.Errno(rc))
	}
}
