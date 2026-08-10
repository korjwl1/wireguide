//go:build darwin

package elevate

import (
	"context"
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
// Installs (or restarts) the LaunchDaemon via a macOS native admin dialog.
// The plist sets RunAtLoad=false, so launchd never starts the helper on its
// own — the helper's lifetime is tied to the GUI's. That means the admin
// prompt appears on first launch and again on any launch that finds no live
// helper socket (i.e. after the helper self-exited when the GUI closed).
// This is the intended trade: no invisible root process outliving the app.
//
// A live socket short-circuits the whole path (step 1), so relaunching the
// GUI while a tunnel is still up does NOT re-prompt.
//
// ctx governs ONLY the post-install socket-readiness polling. The osascript
// admin dialog is intentionally detached from ctx — a user typing their
// password slowly would otherwise have the prompt yanked out from under
// them when the GUI's 30s ensureHelper context expired, producing a
// spurious "Try again?" retry dialog even though the install itself was
// fine. Apple's authopen has no progress signal we can observe, so the
// only safe choice is to let the dialog complete on its own clock.
//
// Flow:
//  1. Socket already live → helper running, return immediately.
//  2. Daemon not installed → install binary + plist + bootstrap (one-time sudo).
//  3. Daemon installed but not running → bootout + bootstrap to restart.
//  4. Dev fallback: if all else fails, osascript spawns helper directly.
func SpawnHelper(ctx context.Context, args Args) error {
	if err := ValidateArgs(args); err != nil {
		return fmt.Errorf("invalid spawn args: %w", err)
	}
	// 1. Already running? (skip check if force-reinstalling after version mismatch)
	if !args.ForceReinstall && isSocketLive(args.SocketPath) {
		slog.Info("helper already running")
		return nil
	}

	// 2-3. Install/restart daemon via a single osascript admin prompt.
	if err := installAndLoadDaemon(ctx, args); err != nil {
		return fmt.Errorf("daemon install failed: %w", err)
	}
	return nil
}

// generatePlistContent returns the canonical plist content this build would
// install. Shared by installAndLoadDaemon (which writes it) and
// PlistNeedsReinstall (which compares it against the on-disk version).
//
// Any change here invalidates every existing install — bump the comparison
// in PlistNeedsReinstall accordingly, or the upgrade path will silently
// leave old plists in place.
func generatePlistContent(exe string, args Args) string {
	uid := os.Getuid()
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
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
    <!-- RunAtLoad is deliberately false. The job stays loaded across
         reboots (the plist lives in /Library/LaunchDaemons), but launchd
         must NOT start it at boot: a running GUI is what signals the user
         wants WireGuide active. A root helper running at boot with no
         window and no tray icon would evaluate Wi-Fi automation rules —
         and could bring a tunnel up — while the user believes the app is
         closed. Users who want WireGuide from boot enable auto_start,
         which installs the GUI LaunchAgent; the GUI then spawns the
         helper through the normal path. installAndLoadDaemon kickstarts
         the job explicitly after bootstrap, since with RunAtLoad=false
         bootstrap only loads it. -->
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <!-- ProcessType omitted to inherit Standard (priority ~31). The
         previous Background setting (priority ~4) caused packet-handling
         latency on contended systems because launchd throttled the
         helper's CPU and timer wakeups. ThrottleInterval still bounds
         respawn rate to once per 5s in case of a crash loop. -->
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardErrorPath</key>
    <string>/var/log/wireguide-helper.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/wireguide-helper.log</string>
</dict>
</plist>
`, daemonLabel, daemonBinary, args.SocketPath, uid, args.DataDir)
}

// PlistNeedsReinstall reports whether the on-disk LaunchDaemon plist differs
// from what this build would write. Used by the GUI launch path to force a
// reinstall when only the plist (not the helper binary version) has changed —
// e.g. after a KeepAlive policy change that an existing version-matched
// helper would otherwise keep running with stale launchd semantics.
//
// Returns false on non-darwin or when SelfPath fails (we can't compute the
// expected content, so we conservatively skip the reinstall trigger).
func PlistNeedsReinstall(args Args) bool {
	existing, err := os.ReadFile(daemonPlist)
	if err != nil {
		// File missing or unreadable — let SpawnHelper handle reinstall
		// via its normal "socket not live" path. Don't force here, since
		// a transient stat error shouldn't prompt for admin password.
		return false
	}
	exe, err := SelfPath()
	if err != nil {
		return false
	}
	expected := generatePlistContent(exe, args)
	return string(existing) != expected
}

// installAndLoadDaemon writes the plist to a temp file (no escaping issues),
// then runs a shell script as root via osascript that copies everything into
// place and bootstraps the daemon. The user sees one password prompt.
//
// ctx is used only for the post-install socket-readiness polling — the
// osascript exec runs against context.Background so a slow password
// entry doesn't get its prompt killed when ensureHelper's outer ctx
// times out.
func installAndLoadDaemon(ctx context.Context, args Args) error {
	exe, err := SelfPath()
	if err != nil {
		return err
	}

	// Write plist to a temp file — avoids heredoc/escaping issues inside
	// the AppleScript string. Go writes it as the current user to /tmp,
	// then the root shell script copies it to /Library/LaunchDaemons/.
	plist := generatePlistContent(exe, args)

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
	// 7. Kickstart it — REQUIRED, because the plist sets RunAtLoad=false.
	//    bootstrap alone only registers the job with launchd; without the
	//    kickstart the process never starts and the socket-readiness poll
	//    below would time out with "daemon installed but socket not live".
	//    -k replaces a survivor from a torn-down previous instance rather
	//    than leaving it running.
	// xattr -d strips com.apple.quarantine from the freshly copied helper
	// binary. macOS adds this attr to anything downloaded (e.g. inside a
	// dmg/zip release) and Gatekeeper blocks quarantined binaries from
	// running as root LaunchDaemons. Trailing `;` (not `&&`): on dev
	// builds without quarantine the command is a no-op + nonzero exit,
	// which we don't want to abort the install.
	//
	// `launchctl bootout` returns immediately, but the actual teardown
	// is asynchronous. If `launchctl bootstrap` runs while the old
	// service is still being torn down, it fails with "service already
	// loaded" and the whole script exits non-zero — which surfaces as
	// the macOS "An error occurred. Try again?" osascript dialog the
	// user has been hitting on every install. The polling loop after
	// bootout waits up to 2 seconds for `launchctl print` to stop
	// finding the service, then bootstrap races no longer occur.
	shellScript := fmt.Sprintf(
		`mkdir -p /Library/PrivilegedHelperTools && `+
			`cp -f %s %s && `+
			`xattr -d com.apple.quarantine %s 2>/dev/null; `+
			`chown root:wheel %s && `+
			`chmod 755 %s && `+
			`cp -f %s %s && `+
			`chown root:wheel %s && `+
			`chmod 644 %s && `+
			`launchctl bootout system/%s 2>/dev/null; `+
			`i=0; while [ $i -lt 20 ] && launchctl print system/%s >/dev/null 2>&1; do sleep 0.1; i=$((i+1)); done; `+
			`launchctl bootstrap system %s && `+
			`launchctl kickstart -k system/%s`,
		shellQuote(exe), shellQuote(daemonBinary),
		shellQuote(daemonBinary),
		shellQuote(daemonBinary),
		shellQuote(daemonBinary),
		shellQuote(tmpPlist), shellQuote(daemonPlist),
		shellQuote(daemonPlist),
		shellQuote(daemonPlist),
		daemonLabel,
		daemonLabel,
		shellQuote(daemonPlist),
		daemonLabel,
	)

	escaped := strings.ReplaceAll(shellScript, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	osascriptCmd := fmt.Sprintf(
		`do shell script "%s" with administrator privileges with prompt "WireGuide needs administrator access to install its VPN helper service.\n\nThe helper runs as a background service to manage VPN tunnels, firewall rules, and network configuration. This prompt appears on first launch or after an app update."`,
		escaped,
	)

	slog.Info("installing LaunchDaemon (one-time admin prompt)")
	// Detach osascript from ctx — see SpawnHelper doc for why.
	if err := exec.Command("osascript", "-e", osascriptCmd).Run(); err != nil {
		return fmt.Errorf("osascript install: %w", err)
	}

	// Wait for daemon socket to come up. Honour ctx so a shutdown
	// during this wait exits promptly instead of dragging out 6s.
	for i := 0; i < 30; i++ {
		select {
		case <-ctx.Done():
			return fmt.Errorf("install wait cancelled: %w", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
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

// shellQuote wraps a value in single quotes, escaping embedded single quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
