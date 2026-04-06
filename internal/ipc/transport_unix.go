//go:build darwin || linux || freebsd

package ipc

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// Listen creates a Unix socket listener at addr.
// If ownerUID >= 0, chowns the socket to that UID and sets mode 0600.
func Listen(addr string, ownerUID int) (net.Listener, error) {
	// Ensure parent directory exists with restrictive permissions (0700)
	// to prevent other users from placing symlinks or interfering with
	// the socket on multi-user systems.
	if dir := filepath.Dir(addr); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dir, err)
		}
		if err := os.Chmod(dir, 0700); err != nil {
			// Non-fatal: we may not own the directory (e.g. system temp dir).
			// The ownership check below is the real security boundary.
			slog.Debug("chmod parent dir failed (non-fatal)", "dir", dir, "error", err)
		}

		// Verify the parent directory is owned by the current effective user
		// to prevent an attacker from pre-creating the directory.
		fi, err := os.Stat(dir)
		if err != nil {
			return nil, fmt.Errorf("stat dir %s: %w", dir, err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, fmt.Errorf("cannot determine owner of %s", dir)
		}
		if st.Uid != uint32(os.Geteuid()) {
			return nil, fmt.Errorf("refusing to use %s: owned by UID %d, expected %d", dir, st.Uid, os.Geteuid())
		}
	}

	// Unconditionally remove any existing socket/file at the path.
	// The parent directory (0700, ownership-verified) is the real security
	// boundary — no TOCTOU-prone Lstat check needed here.
	if err := os.Remove(addr); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale socket %s: %w", addr, err)
	}

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
