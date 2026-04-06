//go:build darwin

package elevate

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	daemonLabel  = "com.wireguide.helper"
	daemonPlist  = "/Library/LaunchDaemons/" + daemonLabel + ".plist"
	daemonBinary = "/Library/PrivilegedHelperTools/" + daemonLabel
)

// SpawnHelper starts the privileged helper process.
//
// On first launch: installs the LaunchDaemon (one-time admin password prompt
// via macOS native dialog). After that, the helper starts at boot via launchd
// and the app never asks for a password again.
//
// Flow:
//  1. Socket already live → helper running, return immediately.
//  2. Daemon not installed → install binary + plist + bootstrap (one-time sudo).
//  3. Daemon installed but not running → bootout + bootstrap to restart.
//  4. Dev fallback: if all else fails, osascript spawns helper directly.
func SpawnHelper(args Args) error {
	// 1. Already running?
	if isSocketLive(args.SocketPath) {
		slog.Info("helper already running")
		return nil
	}

	// 2-3. Install/restart daemon via a single osascript admin prompt.
	if err := installAndLoadDaemon(args); err != nil {
		slog.Warn("daemon install/load failed, falling back to direct spawn", "error", err)
		// 4. Dev fallback.
		return spawnViaOsascript(args)
	}
	return nil
}

// installAndLoadDaemon writes the plist to a temp file (no escaping issues),
// then runs a shell script as root via osascript that copies everything into
// place and bootstraps the daemon. The user sees one password prompt.
func installAndLoadDaemon(args Args) error {
	exe, err := SelfPath()
	if err != nil {
		return err
	}

	// Write plist to a temp file — avoids heredoc/escaping issues inside
	// the AppleScript string. Go writes it as the current user to /tmp,
	// then the root shell script copies it to /Library/LaunchDaemons/.
	uid := os.Getuid()
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>--helper</string>
        <string>--socket=%s</string>
        <string>--uid=%d</string>
        <string>--data-dir=%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/wireguide-helper.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/wireguide-helper.log</string>
</dict>
</plist>
`, daemonLabel, daemonBinary, args.SocketPath, uid, args.DataDir)

	tmpPlist := filepath.Join(os.TempDir(), daemonLabel+".plist")
	if err := os.WriteFile(tmpPlist, []byte(plist), 0644); err != nil {
		return fmt.Errorf("write temp plist: %w", err)
	}
	defer os.Remove(tmpPlist)

	// Validate plist syntax before attempting install.
	if out, err := exec.Command("plutil", "-lint", tmpPlist).CombinedOutput(); err != nil {
		return fmt.Errorf("plist validation failed: %s", strings.TrimSpace(string(out)))
	}

	// Single shell script that does everything as root:
	// 1. Create target directory
	// 2. Copy binary
	// 3. Copy plist (from our validated temp file)
	// 4. Set ownership/permissions
	// 5. Bootout old daemon (ignore errors — may not exist)
	// 6. Bootstrap new daemon
	shellScript := fmt.Sprintf(
		`mkdir -p /Library/PrivilegedHelperTools && `+
			`cp -f %s %s && `+
			`chown root:wheel %s && `+
			`chmod 755 %s && `+
			`cp -f %s %s && `+
			`chown root:wheel %s && `+
			`chmod 644 %s && `+
			`launchctl bootout system/%s 2>/dev/null; `+
			`launchctl bootstrap system %s`,
		shellQuote(exe), shellQuote(daemonBinary),
		shellQuote(daemonBinary),
		shellQuote(daemonBinary),
		shellQuote(tmpPlist), shellQuote(daemonPlist),
		shellQuote(daemonPlist),
		shellQuote(daemonPlist),
		daemonLabel,
		shellQuote(daemonPlist),
	)

	escaped := strings.ReplaceAll(shellScript, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	osascriptCmd := fmt.Sprintf(
		`do shell script "%s" with administrator privileges with prompt "WireGuide needs to install its helper service (one-time setup)."`,
		escaped,
	)

	slog.Info("installing LaunchDaemon (one-time admin prompt)")
	if err := exec.Command("osascript", "-e", osascriptCmd).Run(); err != nil {
		return fmt.Errorf("osascript install: %w", err)
	}

	// Wait for daemon socket to come up.
	for i := 0; i < 30; i++ {
		time.Sleep(200 * time.Millisecond)
		if isSocketLive(args.SocketPath) {
			slog.Info("LaunchDaemon installed and running")
			return nil
		}
	}
	return fmt.Errorf("daemon installed but socket not live after 6s")
}

// isSocketLive checks whether the helper socket accepts a connection.
func isSocketLive(socketPath string) bool {
	conn, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// spawnViaOsascript launches the helper directly with root privileges via
// osascript. Used during development when the LaunchDaemon is not installed.
func spawnViaOsascript(args Args) error {
	exe, err := SelfPath()
	if err != nil {
		return err
	}

	logPath := "/var/log/wireguide-helper.log"
	cmd := fmt.Sprintf(
		`(echo '' ; echo '==== helper spawn ====' ; date ; %s --helper --socket=%s --uid=%d --data-dir=%s) >> %s 2>&1 & disown`,
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
