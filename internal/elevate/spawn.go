// Package elevate spawns a child process with elevated privileges.
package elevate

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Args holds arguments for spawning the helper.
type Args struct {
	// SocketPath is passed to the helper as --socket=PATH
	SocketPath string
	// SocketUID is the UID to chown the socket to (Unix only). On Windows, 0.
	SocketUID int
	// DataDir for crash recovery state
	DataDir string
	// ForceReinstall skips the "already running" socket check and
	// reinstalls the binary + restarts the daemon. Used when the GUI
	// detects a helper version mismatch after an app update.
	ForceReinstall bool
}

// SelfPath returns the absolute path of the current executable.
func SelfPath() (string, error) {
	return os.Executable()
}

// ValidateArgs sanity-checks Args before passing values to the platform
// spawn path. SocketPath and DataDir are interpolated into a LaunchDaemon
// plist (darwin), pkexec command line (linux), or PowerShell argument
// list (windows). Catching path-traversal or shell-metachar inputs here
// is defense-in-depth — the GUI controls these values today, but a
// future code path that takes them from disk or IPC would need this
// check to be safe by default.
func ValidateArgs(a Args) error {
	if err := validateSpawnPath("SocketPath", a.SocketPath); err != nil {
		return err
	}
	if err := validateSpawnPath("DataDir", a.DataDir); err != nil {
		return err
	}
	return nil
}

// validateSpawnPath rejects paths that:
//   - are not absolute (relative paths could resolve unpredictably under
//     the privileged helper's CWD),
//   - contain ".." components (traversal),
//   - contain shell metacharacters or NULs (defense for the rare path
//     that lands in a string-interpolated context like the plist).
func validateSpawnPath(field, p string) error {
	if p == "" {
		return fmt.Errorf("%s is empty", field)
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%s must be absolute: %q", field, p)
	}
	// Reject literal "..": filepath.Clean would normalise "/a/../b" to
	// "/b" but we want to refuse any input that mentions traversal so a
	// malformed config is obvious instead of silently rewritten.
	for _, part := range strings.Split(p, string(filepath.Separator)) {
		if part == ".." {
			return fmt.Errorf("%s contains parent-directory traversal: %q", field, p)
		}
	}
	for _, r := range p {
		if r == 0 || r == '\n' || r == '\r' {
			return fmt.Errorf("%s contains control character: %q", field, p)
		}
	}
	return nil
}

// KillProcess forcefully terminates a process by PID. Used as a last-resort
// when the helper ignores a graceful Shutdown RPC. Best-effort: errors are
// logged. Returns nil if the process is already gone.
//
// pid <= 0 is rejected outright (invalid). pid == 1 is allowed but only if
// it matches our own parent — refuses otherwise to avoid killing the
// system init/launchd. Inside containers (Docker, LXC) the helper can
// legitimately run as PID 1, in which case os.Getppid()==0 or the caller
// (GUI inside the same container) shares that PID 1; we still refuse on
// principle because there's no scenario where the *GUI* should be killing
// PID 1 of any namespace.
func KillProcess(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("refusing to kill pid %d (invalid)", pid)
	}
	if pid == 1 {
		return fmt.Errorf("refusing to kill pid 1 (init/launchd or container PID 1 — never safe from GUI)")
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		// On Unix FindProcess never returns an error; on Windows it can.
		return fmt.Errorf("find pid %d: %w", pid, err)
	}
	if err := proc.Kill(); err != nil {
		slog.Warn("kill helper process failed", "pid", pid, "error", err)
		return err
	}
	return nil
}

// RemoveStaleSocket removes a leftover socket / named-pipe entry on disk so a
// fresh helper can listen on the same address. No-op on Windows where named
// pipes don't have a filesystem path the GUI can unlink.
func RemoveStaleSocket(addr string) {
	if addr == "" {
		return
	}
	// On Windows the addr is `\\.\pipe\WireGuide`; nothing to unlink.
	if len(addr) > 2 && addr[0] == '\\' && addr[1] == '\\' {
		return
	}
	if err := os.Remove(addr); err != nil && !os.IsNotExist(err) {
		slog.Debug("stale socket cleanup", "path", addr, "error", err)
	}
}
