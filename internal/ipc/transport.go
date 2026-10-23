package ipc

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// LegacyDarwinSocketPath is where macOS helpers before socket activation
// listened. It is kept for migration probes (an old helper may still be
// running on it after an upgrade) and as the non-launchd fallback location
// for dev runs, tests and old plists that pass it explicitly.
const LegacyDarwinSocketPath = "/var/run/wireguide/wireguide.sock"

// DarwinSocketPath is the launchd-owned socket the LaunchDaemon plist
// declares under Sockets. It sits directly in /var/run because launchd does
// not create intermediate directories for SockPathName.
const DarwinSocketPath = "/var/run/com.wireguide.helper.sock"

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

		// The path is fixed by the plist's SockPathName, so it wins over
		// XDG_RUNTIME_DIR: an activated helper serves only launchd's socket.
		if runtime.GOOS == "darwin" {
			// macOS: launchd binds this socket itself (plist Sockets, mode 0600,
			// owned by the GUI user) and starts the root helper on the first
			// connect, so no admin prompt is needed to bring the helper up.
			// It must sit directly in /var/run: launchd does not create
			// parent directories. See LegacyDarwinSocketPath for the old
			// location.
			return DarwinSocketPath
		}

		// M18: Prefer $XDG_RUNTIME_DIR (typically /run/user/<uid>/) which is
		// a per-user tmpfs with restricted permissions.
		if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
			return filepath.Join(runtimeDir, "wireguide-"+uidStr+".sock")
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
		// Returning a best-effort path on failure (instead of panicking)
		// keeps a hostile /tmp from killing the helper process at startup
		// — the subsequent listen will fail with a clear error which the
		// caller surfaces, rather than a stack trace. The Listen() path
		// also re-checks ownership before binding, so the socket can't
		// be hijacked even if this function returns a tainted path.
		if err := verifyDirOwnership(dir, uid); err != nil {
			slog.Error("IPC socket directory ownership check failed; subsequent Listen will fail with a clear error",
				"dir", dir, "error", err)
		}
		return filepath.Join(dir, "wireguide.sock")
	}
}
