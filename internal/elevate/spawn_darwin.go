//go:build darwin

package elevate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
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
//  2. Installed daemon identical to this build (binary hash + plist) →
//     kickstart-only admin script. No binary churn: rewriting an unchanged
//     daemon re-registers it with Background Task Management on every
//     launch, which on macOS 26 (Tahoe) spams "Background Items Added"
//     notifications and risks tripping BTM's disallow state (issue #41).
//     If the kickstart fails (job not bootstrapped, BTM blocked), the same
//     script escalates to the full purge+install without a second prompt.
//  3. Anything else (not installed, version change, plist drift) → purge
//     the old binary+plist FIRST, then install fresh + bootstrap +
//     kickstart. The purge is deliberate: replacing an ad-hoc-signed
//     binary in place invalidates the BTM record keyed to the old
//     binary's identity and launchd then refuses to start the daemon —
//     the root cause of the issue #41 prompt loop. Removing the files
//     resets the record so the fresh install registers cleanly (this is
//     exactly the manual fix that worked for the reporter).
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

	// Full install script, run as root:
	// 1. Bootout old daemon (ignore errors — may not exist), then wait for
	//    launchd's asynchronous teardown to finish. Bootout comes FIRST —
	//    before any file changes — because overwriting the binary of a
	//    still-running signed process makes the kernel kill it (code
	//    signature invalidation) and races launchd's KeepAlive logic.
	//    If `launchctl bootstrap` ran while the old service was still
	//    being torn down, it would fail with "service already loaded" and
	//    the whole script exits non-zero — which surfaces as the macOS
	//    "An error occurred. Try again?" osascript dialog the user used to
	//    hit on every install. The polling loop waits up to 5 seconds
	//    (old-helper cleanup can take seconds per active tunnel) for
	//    `launchctl print` to stop finding the service.
	// 2. PURGE the old binary + plist instead of overwriting in place.
	//    Background Task Management keys its record to the ad-hoc-signed
	//    binary's identity (cdhash); an in-place overwrite leaves a record
	//    that no longer matches and launchd then refuses to start the
	//    daemon (issue #41). Removing the files resets the record; the
	//    fresh copy below registers as a new, cleanly-approved item.
	// 3. Create target directory, copy binary, copy plist (from our
	//    validated temp file), set ownership/permissions.
	// 4. Bootstrap new daemon.
	// 5. Kickstart it — REQUIRED, because the plist sets RunAtLoad=false.
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
	fullInstall := fmt.Sprintf(
		`launchctl bootout system/%s 2>/dev/null; `+
			`i=0; while [ $i -lt 50 ] && launchctl print system/%s >/dev/null 2>&1; do sleep 0.1; i=$((i+1)); done; `+
			`rm -f %s %s && `+
			`mkdir -p /Library/PrivilegedHelperTools && `+
			`cp -f %s %s && `+
			`xattr -d com.apple.quarantine %s 2>/dev/null; `+
			`chown root:wheel %s && `+
			`chmod 755 %s && `+
			`cp -f %s %s && `+
			`chown root:wheel %s && `+
			`chmod 644 %s && `+
			`launchctl bootstrap system %s && `+
			`launchctl kickstart -k system/%s`,
		daemonLabel,
		daemonLabel,
		shellQuote(daemonBinary), shellQuote(daemonPlist),
		shellQuote(exe), shellQuote(daemonBinary),
		shellQuote(daemonBinary),
		shellQuote(daemonBinary),
		shellQuote(daemonBinary),
		shellQuote(tmpPlist), shellQuote(daemonPlist),
		shellQuote(daemonPlist),
		shellQuote(daemonPlist),
		shellQuote(daemonPlist),
		daemonLabel,
	)

	// When the installed daemon is byte-identical to what we would install
	// (binary hash + plist content), skip the reinstall entirely and just
	// kickstart the already-registered job — the common "cold app launch,
	// helper self-exited earlier" path. This keeps the BTM record stable
	// across launches. `|| { fullInstall; }` escalates in the SAME admin
	// session if the kickstart fails (job not bootstrapped after a manual
	// bootout, BTM disallowed, …), so the user never pays a second prompt.
	shellScript := fullInstall
	if daemonUpToDate(exe, plist) {
		slog.Info("installed helper matches this build — kickstart-only path")
		shellScript = fmt.Sprintf(`launchctl kickstart -k system/%s 2>/dev/null || { %s; }`,
			daemonLabel, fullInstall)
	}

	escaped := strings.ReplaceAll(shellScript, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	osascriptCmd := fmt.Sprintf(
		`do shell script "%s" with administrator privileges with prompt "WireGuide needs administrator access to install its VPN helper service.\n\nThe helper runs as a background service to manage VPN tunnels, firewall rules, and network configuration. This prompt appears on first launch or after an app update."`,
		escaped,
	)

	slog.Info("installing LaunchDaemon (one-time admin prompt)")
	// Detach osascript from ctx — see SpawnHelper doc for why.
	// CombinedOutput, not Run: `do shell script` reports the failing
	// command's stderr (launchctl error codes included) in osascript's
	// own stderr, and swallowing it is why issue #41 looped with zero
	// diagnostic surface. The tail of the output rides along in the
	// returned error and ends up in the GUI's retry dialog.
	if out, err := exec.Command("osascript", "-e", osascriptCmd).CombinedOutput(); err != nil {
		return fmt.Errorf("osascript install: %w — %s", err, tailOf(out, 500))
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
	return fmt.Errorf("daemon installed but socket not live after 6s — " +
		"the helper did not start; check /var/log/wireguide-helper.log, and " +
		"System Settings > General > Login Items & Extensions for a disabled " +
		"WireGuide (or \"Unknown Developer\") background item blocking launchd")
}

// daemonUpToDate reports whether the installed daemon is byte-identical to
// what this build would install: same binary content (SHA-256) and same
// plist content. Used to route SpawnHelper onto the kickstart-only path.
// Any read error (not installed yet, permissions) → false → full install.
func daemonUpToDate(exe, wantPlist string) bool {
	onDisk, err := os.ReadFile(daemonPlist)
	if err != nil || !bytes.Equal(onDisk, []byte(wantPlist)) {
		return false
	}
	selfSum, err := fileSHA256(exe)
	if err != nil {
		return false
	}
	installedSum, err := fileSHA256(daemonBinary)
	if err != nil {
		return false
	}
	return bytes.Equal(selfSum, installedSum)
}

// fileSHA256 returns the SHA-256 digest of the file at path.
func fileSHA256(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// tailOf returns the last n bytes of out as a trimmed string — launchctl /
// osascript put the interesting error last, and the retry dialog has
// limited room.
func tailOf(out []byte, n int) string {
	s := strings.TrimSpace(string(out))
	if len(s) > n {
		s = "…" + s[len(s)-n:]
	}
	return s
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
