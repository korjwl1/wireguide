//go:build darwin

package elevate

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

const (
	daemonLabel   = "com.wireguide.helper"
	daemonPlist   = "/Library/LaunchDaemons/" + daemonLabel + ".plist"
	daemonBinary  = "/Library/PrivilegedHelperTools/" + daemonLabel
)

// SpawnHelper starts the privileged helper process. It tries these methods
// in order:
//
//  1. LaunchDaemon (if installed via `brew install`): `launchctl kickstart`
//     — no password prompt, daemon restarts automatically on crash.
//  2. osascript fallback (dev builds / manual install): prompts for admin
//     password via the native macOS dialog every time.
//
// Method 1 is the production path. Method 2 exists so `./bin/wireguide`
// works during development without installing a LaunchDaemon.
func SpawnHelper(args Args) error {
	// Try LaunchDaemon first — instant, no password prompt.
	if isDaemonInstalled() {
		slog.Info("starting helper via LaunchDaemon")
		// kickstart -k kills the existing instance (if any) and starts a fresh one.
		cmd := exec.Command("launchctl", "kickstart", "-k", "system/"+daemonLabel)
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("launchctl kickstart failed, falling back to osascript",
				"error", err, "output", strings.TrimSpace(string(out)))
		} else {
			return nil // daemon started successfully
		}
	}

	// Fallback: osascript with administrator privileges.
	return spawnViaOsascript(args)
}

// isDaemonInstalled checks whether the LaunchDaemon plist and binary are
// both present. If either is missing, the daemon is not installed.
func isDaemonInstalled() bool {
	if _, err := os.Stat(daemonPlist); err != nil {
		return false
	}
	if _, err := os.Stat(daemonBinary); err != nil {
		return false
	}
	return true
}

// spawnViaOsascript launches the helper with root privileges via osascript.
// Used during development or when the LaunchDaemon is not installed.
func spawnViaOsascript(args Args) error {
	exe, err := SelfPath()
	if err != nil {
		return err
	}

	logPath := "/var/log/wireguide-helper.log"
	cmd := fmt.Sprintf(
		`(echo ''; echo '==== helper spawn ====' ; date ; %s --helper --socket=%s --uid=%d --data-dir=%s) >> %s 2>&1 & disown`,
		shellQuote(exe), shellQuote(args.SocketPath), args.SocketUID, shellQuote(args.DataDir), shellQuote(logPath),
	)
	escaped := strings.ReplaceAll(cmd, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	script := fmt.Sprintf(
		`do shell script "%s" with administrator privileges with prompt "WireGuide needs administrator privileges to manage VPN tunnels."`,
		escaped,
	)

	return exec.Command("osascript", "-e", script).Run()
}

// shellQuote wraps a value in single quotes, escaping embedded single quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
