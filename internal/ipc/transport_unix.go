//go:build darwin || linux || freebsd

package ipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// Listen creates a Unix socket listener at addr.
// If ownerUID >= 0, chowns the socket to that UID and sets mode 0600.
func Listen(addr string, ownerUID int) (net.Listener, error) {
	// Ensure parent directory exists
	if dir := filepath.Dir(addr); dir != "" {
		os.MkdirAll(dir, 0755)
	}

	// Remove stale socket
	_ = os.Remove(addr)

	l, err := net.Listen("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}

	// Restrict permissions: only owner can read/write
	if err := os.Chmod(addr, 0600); err != nil {
		l.Close()
		return nil, fmt.Errorf("chmod: %w", err)
	}

	// Chown to GUI user so they can connect (helper runs as root)
	if ownerUID >= 0 {
		if err := os.Chown(addr, ownerUID, -1); err != nil {
			l.Close()
			return nil, fmt.Errorf("chown: %w", err)
		}
	}

	return l, nil
}

// Dial connects to a Unix socket.
func Dial(addr string) (net.Conn, error) {
	return net.Dial("unix", addr)
}
