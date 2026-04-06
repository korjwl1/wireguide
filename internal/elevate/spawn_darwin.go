//go:build darwin

package elevate

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
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
	// Try LaunchDaemon first — if the daemon is installed and already
	// running (KeepAlive=true means launchd auto-starts it), we don't
	// need to do anything. Just check if the socket is already live.
	if isDaemonInstalled() {
		slog.Info("LaunchDaemon installed, checking if helper is already running")
		// The daemon should be running via KeepAlive. If for some reason
		// it's not, try kickstart via sudo (will prompt once). But most
		// of the time the daemon is already alive and we just return.
		if isSocketLive(args.SocketPath) {
			slog.Info("helper already running via LaunchDaemon")
			return nil
		}
		// Socket not live — try kickstart. This needs root, so we use
		// osascript to run launchctl as admin (one-time prompt).
		script := fmt.Sprintf(
			`do shell script "launchctl kickstart -k system/%s" with administrator privileges with prompt "WireGuide needs to start its helper service."`,
			daemonLabel,
		)
		if err := exec.Command("osascript", "-e", script).Run(); err != nil {
			slog.Warn("launchctl kickstart via osascript failed, falling back to direct spawn",
				"error", err)
		} else {
			return nil
		}
	}

	// Fallback: osascript with administrator privileges.
	return spawnViaOsascript(args)
}

// isSocketLive checks whether the helper socket exists and accepts a connection.
func isSocketLive(socketPath string) bool {
	conn, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
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
