//go:build darwin

package elevate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SpawnHelper launches the helper binary with root privileges via osascript.
// Uses the native macOS authentication dialog (padlock), no terminal.
// The helper runs in the background; this call returns after the dialog is
// dismissed (or errors out).
func SpawnHelper(args Args) error {
	exe, err := SelfPath()
	if err != nil {
		return err
	}

	// Run the helper in the background via do shell script with privileges.
	// Using "& disown" to detach so osascript returns immediately.
	// Redirect output to log file for debugging. IMPORTANT: use >> (append)
	// not > (truncate) so logs from prior runs are preserved — otherwise
	// every respawn wipes the crash/shutdown evidence from the previous
	// helper instance, which is exactly what we need to diagnose why it died.
	//
	// Use ~/Library/Logs/WireGuide/ instead of /tmp to avoid symlink attacks.
	// The helper runs as root, so writing to a world-writable /tmp path
	// controlled by an attacker could overwrite arbitrary files.
	home, _ := os.UserHomeDir()
	logDir := filepath.Join(home, "Library", "Logs", "WireGuide")
	os.MkdirAll(logDir, 0700)
	logPath := filepath.Join(logDir, "helper.log")
	cmd := fmt.Sprintf(
		`(echo ''; echo '==== helper spawn ====' ; date ; %s --helper --socket=%s --uid=%d --data-dir=%s) >> %s 2>&1 & disown`,
		shellQuote(exe), shellQuote(args.SocketPath), args.SocketUID, shellQuote(args.DataDir), shellQuote(logPath),
	)
	// Escape backslashes and double-quotes for the AppleScript string literal.
	escaped := strings.ReplaceAll(cmd, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	script := fmt.Sprintf(
		`do shell script "%s" with administrator privileges with prompt "WireGuide needs administrator privileges to manage VPN tunnels."`,
		escaped,
	)

	return exec.Command("osascript", "-e", script).Run()
}

// shellQuote wraps a value in single quotes, escaping embedded single quotes
// with the standard shell idiom '\'' (end quote, literal quote, reopen quote).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
