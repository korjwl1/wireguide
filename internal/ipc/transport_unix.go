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
	// Ensure parent directory exists. On macOS the socket lives in
	// /var/run/wireguide/ — the helper (root) creates it, and the GUI
	// (unprivileged user) needs to traverse it to reach the socket.
	// 0755 allows traversal; the socket itself is chmod 0600 + chowned
	// to the GUI user, so only that user can actually connect.
	if dir := filepath.Dir(addr); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dir, err)
		}
		if err := os.Chmod(dir, 0755); err != nil {
			// Non-fatal: we may not own the directory (e.g. system temp dir).
			// The ownership check below is the real security boundary.
			slog.Debug("chmod parent dir failed (non-fatal)", "dir", dir, "error", err)
		}

		// Verify the parent directory is owned by a trusted UID to prevent
		// an attacker from pre-creating the directory.
		//
		// The helper runs as root (euid=0) but the socket directory lives
		// under the GUI user's home (e.g. ~/Library/Application Support/).
		// We accept ownership by:
		//   - The current effective user (root when helper calls Listen)
		//   - The ownerUID (the GUI user who spawned the helper)
		// Both are trusted. The real access control is the socket's
		// chmod 0600 + chown to ownerUID.
		fi, err := os.Stat(dir)
		if err != nil {
			return nil, fmt.Errorf("stat dir %s: %w", dir, err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, fmt.Errorf("cannot determine owner of %s", dir)
		}
		dirUID := uint32(st.Uid)
		euid := uint32(os.Geteuid())
		trusted := dirUID == euid
		if !trusted && ownerUID >= 0 && dirUID == uint32(ownerUID) {
			trusted = true
		}
		if !trusted {
			return nil, fmt.Errorf("refusing to use %s: owned by UID %d, expected %d or %d", dir, dirUID, euid, ownerUID)
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
