package ipc

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// DefaultSocketPath returns the default socket/pipe address for this OS+user.
func DefaultSocketPath() string {
	switch runtime.GOOS {
	case "windows":
		// H14: Use a fixed well-known pipe name instead of deriving from the
		// USERNAME environment variable (which can be spoofed). Access control
		// is handled by the SDDL on the pipe itself, so the name does not
		// need to encode identity.
		return `\\.\pipe\wireguide`
	default:
		uid := os.Getuid()
		uidStr := strconv.Itoa(uid)

		// M18: Prefer $XDG_RUNTIME_DIR (typically /run/user/<uid>/) which is
		// a per-user tmpfs with restricted permissions.
		if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
			return filepath.Join(runtimeDir, "wireguide-"+uidStr+".sock")
		}

		if runtime.GOOS == "darwin" {
			// macOS: use /var/run/wireguide/ — the helper runs as root (via
			// LaunchDaemon or osascript) and creates this directory. The GUI
			// connects as an unprivileged user; the helper chowns the socket
			// so the GUI can read/write it. This path is stable across app
			// restarts and doesn't pollute the user's home directory.
			return "/var/run/wireguide/wireguide.sock"
		}

		// Linux fallback: create a private subdirectory under /tmp with mode 0700
		// so other users cannot place symlinks or interfere with the socket.
		dir := filepath.Join("/tmp", "wireguide-"+uidStr)
		if err := os.MkdirAll(dir, 0700); err != nil {
			slog.Error("failed to create IPC socket directory", "dir", dir, "error", err)
			return filepath.Join(dir, "wireguide.sock") // return best-effort path
		}
		// Ensure the directory has the correct permissions even if it already existed.
		if err := os.Chmod(dir, 0700); err != nil {
			slog.Warn("failed to set IPC socket directory permissions", "dir", dir, "error", err)
		}
		// Verify ownership to prevent an attacker from pre-creating the directory.
		if err := verifyDirOwnership(dir, uid); err != nil {
			slog.Error("IPC socket directory ownership check failed", "dir", dir, "error", err)
			panic(err.Error())
		}
		return filepath.Join(dir, "wireguide.sock")
	}
}