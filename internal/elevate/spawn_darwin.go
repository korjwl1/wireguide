//go:build darwin

package elevate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/update"
)

const (
	daemonLabel  = "com.wireguide.helper"
	daemonPlist  = "/Library/LaunchDaemons/" + daemonLabel + ".plist"
	daemonBinary = "/Library/PrivilegedHelperTools/" + daemonLabel
)

// SpawnHelper makes sure the privileged helper is reachable.
//
// The LaunchDaemon owns the helper's socket (launchd socket activation,
// RunAtLoad=false): launchd binds /var/run/com.wireguide.helper.sock from
// boot and starts the helper when something connects to it. So with an
// up-to-date install no administrator authorization is needed at all — after
// confirming the job is loaded (unprivileged `launchctl print`), the dial in
// waitForHelper IS the start request. The helper's lifetime is still tied to
// the GUI (it idles out after the GUI goes away), and it stays dormant — no
// automation — until a GUI attaches, so no invisible root process acts on its
// own.
//
// The administrator prompt appears only to install or repair: first install,
// an app update (new binary or plist), a job that is not loaded or whose
// socket launchd could not bind, or a helper that does not come up in time.
//
// A compatible RPC response short-circuits the whole path (step 1), so relaunching the
// GUI while a tunnel is still up does NOT re-prompt.
//
// ctx cancels readiness polling, but authorization is allowed to complete
// without a deadline so a slow password entry does not become a failed install.
//
// Upgrades unload the old job before replacing its files. This avoids
// rewriting a running executable; it does not guarantee that macOS will reset
// background-item approval.
func SpawnHelper(ctx context.Context, args Args) error {
	if err := ValidateArgs(args); err != nil {
		return fmt.Errorf("invalid spawn args: %w", err)
	}
	// 1. Already running? (skip check if force-reinstalling after version mismatch)
	if !args.ForceReinstall && helperResponsive(ctx, args.SocketPath) == nil {
		slog.Info("helper already running")
		return nil
	}

	// 2-3. Install/restart daemon via a bounded authorization attempts.
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
         must NOT start it at boot: a root helper running at boot with no
         window and no tray icon is exactly what a user who closed the app
         does not expect. The Sockets entry below is what starts it: launchd
         binds the socket at boot and launches the helper when something
         connects, so the app brings it up just by dialing — no
         administrator prompt. The helper adopts that socket
         (launch_activate_socket) instead of creating its own, serves only
         the owning uid (SockPathOwner, mode 0600, plus the peer-credential
         check), stays dormant until a GUI attaches, and idles out when the
         GUI goes away. -->
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <dict>
        <!-- SuccessfulExit alone implies an initial launch even when
             RunAtLoad is false. Gate crash restarts on demand (a connect
             to the socket below). -->
        <key>AfterInitialDemand</key>
        <true/>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>Sockets</key>
    <dict>
        <key>Listeners</key>
        <dict>
            <!-- Directly in /var/run: launchd does not create parent
                 directories. 384 is 0600 (plists have no octal). -->
            <key>SockPathName</key>
            <string>%s</string>
            <key>SockType</key>
            <string>stream</string>
            <key>SockPathMode</key>
            <integer>384</integer>
            <key>SockPathOwner</key>
            <integer>%d</integer>
        </dict>
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
`, daemonLabel, daemonBinary, args.SocketPath, uid, args.DataDir, ipc.DarwinSocketPath, uid)
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

// installAndLoadDaemon brings the LaunchDaemon to a state where the helper
// answers on its socket.
//
// Up-to-date install (same binary and plist): no authorization. The job is
// loaded from boot and owns the socket, so confirming that with unprivileged
// launchctl and then waiting on the socket is enough — the connect starts the
// helper. Only if that fails (job not loaded, socket error, wait timed out) does
// it fall back to the administrator full repair, once.
//
// Anything else: write the plist to a temp file (no escaping issues), then run
// a shell script as root via osascript that copies everything into place and
// bootstraps the daemon.
//
// ctx is used only for post-install socket-readiness polling. Authorization
// is synchronous and has no deadline; the GUI starts its readiness deadline
// after this function returns.
func installAndLoadDaemon(ctx context.Context, args Args) error {
	exe, err := SelfPath()
	if err != nil {
		return err
	}

	// Write plist to a temp file — avoids heredoc/escaping issues inside
	// the AppleScript string. Go writes it as the current user to /tmp,
	// then the root shell script copies it to /Library/LaunchDaemons/.
	plist := generatePlistContent(exe, args)

	tmpDir, err := os.MkdirTemp("", daemonLabel+"-*")
	if err != nil {
		return fmt.Errorf("create temp plist directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	tmpPlist := filepath.Join(tmpDir, "helper.plist")
	if err := os.WriteFile(tmpPlist, []byte(plist), 0600); err != nil {
		return fmt.Errorf("write temp plist: %w", err)
	}

	// Validate plist syntax before attempting install.
	if out, err := exec.Command("plutil", "-lint", tmpPlist).CombinedOutput(); err != nil {
		return fmt.Errorf("plist validation failed: %s", strings.TrimSpace(string(out)))
	}

	upToDate := !args.ForceReinstall && daemonUpToDate(exe, plist)
	ops := daemonOps{
		checkEnabled: checkDaemonEnabled,
		loaded:       checkDaemonLoaded,
		authorize:    runDaemonAuthorization,
	}
	err = startDaemonWithRepair(ctx, upToDate, func(fast bool) error {
		return startDaemonStep(ctx, ops, exe, tmpPlist, fast)
	}, func(ctx context.Context) error {
		return waitForHelper(ctx, args.SocketPath, 30*time.Second)
	})
	if err == nil || errors.Is(err, ErrAuthorizationCanceled) || errors.Is(err, context.Canceled) {
		return err
	}
	if disabled := checkDaemonEnabled(ctx); disabled != nil {
		return disabled
	}
	return fmt.Errorf("%w\nHelper state: %s. Check /var/log/wireguide-helper.log and System Settings > General > Login Items & Extensions; allow WireGuide if macOS has blocked it", err, daemonStateSummary(ctx))
}

// daemonOps are the external effects of a start attempt, injectable so the
// no-prompt fast path can be tested without launchd or osascript.
type daemonOps struct {
	checkEnabled func(context.Context) error
	loaded       func(context.Context) error
	authorize    func(shellScript string) error
}

// startDaemonStep is one start attempt. The fast attempt never authorizes: it
// only confirms the job is loaded with a healthy socket, because the dial that
// follows is what makes launchd start the helper. The full attempt runs the
// root install script behind one administrator prompt.
func startDaemonStep(ctx context.Context, ops daemonOps, exe, tmpPlist string, fast bool) error {
	if err := ops.checkEnabled(ctx); err != nil {
		return err
	}
	if fast {
		return ops.loaded(ctx)
	}
	return ops.authorize(daemonInstallScript(exe, tmpPlist))
}

// A failed fast attempt (job not loaded, socket error, helper not responding)
// gets one full administrator repair. A failed full repair returns to the
// user's Retry/Quit decision; it never loops itself.
func startDaemonWithRepair(ctx context.Context, fast bool, start func(bool) error, ready func(context.Context) error) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := start(fast)
		if err == nil {
			err = ready(ctx)
		}
		if err == nil {
			return nil
		}
		if !fast || errors.Is(err, ErrAuthorizationCanceled) || errors.Is(err, ErrBackgroundDisabled) || ctx.Err() != nil {
			return err
		}
		slog.Warn("helper passive start failed; attempting one full repair", "error", err)
		fast = false
	}
}

// checkDaemonLoaded confirms, without privileges, that the LaunchDaemon is
// loaded and launchd bound its socket. `launchctl print system/...` works for
// an ordinary user.
func checkDaemonLoaded(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "launchctl", "print", "system/"+daemonLabel).CombinedOutput()
	return daemonLoadedFromPrint(out, err)
}

// daemonLoadedFromPrint interprets `launchctl print` output. A missing
// `sockets` block is not an error (the readiness wait decides); an `error =`
// inside it means launchd failed to bind the socket and no connect will ever
// start the helper.
func daemonLoadedFromPrint(out []byte, err error) error {
	if err != nil {
		return fmt.Errorf("LaunchDaemon %s is not loaded: %w", daemonLabel, err)
	}
	inSockets, depth := false, 0
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(line)
		if !inSockets {
			// Top-level job field only: tab-indented once, not a nested block.
			if t == "sockets = {" && strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "\t\t") {
				inSockets, depth = true, 1
			}
			continue
		}
		if strings.HasPrefix(t, "error =") {
			return fmt.Errorf("launchd could not bind the helper socket: %s", t)
		}
		depth += strings.Count(t, "{") - strings.Count(t, "}")
		if depth <= 0 {
			break
		}
	}
	return nil
}

func runDaemonAuthorization(shellScript string) error {
	escaped := strings.ReplaceAll(shellScript, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	script := fmt.Sprintf(`do shell script "%s" with administrator privileges with prompt "WireGuide needs administrator access to start or repair its VPN helper service."`, escaped)
	slog.Info("starting LaunchDaemon (administrator authorization)")
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "(-128)") {
			return fmt.Errorf("%w: %s", ErrAuthorizationCanceled, tailOf(out, 500))
		}
		return fmt.Errorf("helper service command failed: %w — %s", err, tailOf(out, 500))
	}
	return nil
}

// A reachable Unix socket is not sufficient: verify a compatible, responsive
// helper without creating a GUI lease that changes the shutdown grace period.
//
// With socket activation the probe's connect is what starts the helper, so
// when launchd's socket file exists the probe waits long enough to cover
// launchd's ThrottleInterval plus helper startup (crash recovery runs before
// Serve); otherwise there is nothing to wait for.
func helperResponsive(ctx context.Context, addr string) error {
	timeout := time.Second
	if _, err := os.Stat(addr); err == nil {
		timeout = 15 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ping, err := ipc.ProbeHelper(probeCtx, addr)
	if err != nil {
		return err
	}
	if ping.AppVersion != update.CurrentVersion() {
		return fmt.Errorf("helper version %q does not match app %q", ping.AppVersion, update.CurrentVersion())
	}
	return nil
}

func waitForHelper(ctx context.Context, addr string, timeout time.Duration) error {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var lastErr error
	for {
		if err := waitCtx.Err(); err != nil {
			return fmt.Errorf("helper did not become responsive: %w (last probe: %v)", err, lastErr)
		}
		lastErr = helperResponsive(waitCtx, addr)
		if lastErr == nil {
			return nil
		}
		select {
		case <-waitCtx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
}

var disabledDaemonLine = regexp.MustCompile(`(?m)^\s*"` + regexp.QuoteMeta(daemonLabel) + `"\s*=>\s*(?:true|disabled)\s*[,;]?\s*$`)

func checkDaemonEnabled(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "launchctl", "print-disabled", "system").CombinedOutput()
	if err == nil && disabledDaemonLine.Match(out) {
		return fmt.Errorf("%w. Open System Settings > General > Login Items & Extensions and allow WireGuide. If disabled using launchctl, an administrator must re-enable system/com.wireguide.helper", ErrBackgroundDisabled)
	}
	return nil // Unknown state is not evidence that the user disabled it.
}

func daemonStateSummary(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "launchctl", "print", "system/"+daemonLabel).CombinedOutput()
	if err != nil {
		return "not loaded or unavailable"
	}
	var fields []string
	for _, line := range strings.Split(string(out), "\n") {
		// Only top-level fields, not nested resource coalition state.
		if !strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "\t\t") {
			continue
		}
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"state =", "pid =", "last exit code =", "last terminating signal ="} {
			if strings.HasPrefix(line, prefix) {
				fields = append(fields, line)
				break
			}
		}
	}
	if len(fields) == 0 {
		return "loaded, startup details unavailable"
	}
	return strings.Join(fields, "; ")
}

// daemonInstallScript is the full root install/repair. It is separated from
// authorization so its failure paths can be exercised with shell command stubs
// without touching launchd. (bootstrap binds the launchd socket; kickstart then
// starts the helper right away rather than waiting for the first connect. A
// stale socket file left by bootout is simply rebound by launchd.)
func daemonInstallScript(exe, tmpPlist string) string {
	return fmt.Sprintf(
		`launchctl bootout system/%s 2>/dev/null; `+
			`i=0; while [ $i -lt 150 ] && launchctl print system/%s >/dev/null 2>&1; do sleep 0.1; i=$((i+1)); done; `+
			`if [ $i -ge 150 ]; then echo 'WireGuide helper did not unload within 15s; no files were changed' >&2; exit 1; fi; `+
			`rm -f %s %s && `+
			`mkdir -p /Library/PrivilegedHelperTools && `+
			`cp -f %s %s && `+
			`{ xattr -d com.apple.quarantine %s 2>/dev/null || true; } && `+
			`chown root:wheel %s && `+
			`chmod 755 %s && `+
			`cp -f %s %s && `+
			`chown root:wheel %s && `+
			`chmod 644 %s && `+
			`launchctl bootstrap system %s && `+
			`launchctl kickstart system/%s`,
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
}

// daemonUpToDate reports whether the installed daemon is byte-identical to
// what this build would install: same binary content (SHA-256) and same
// plist content. Used to route SpawnHelper onto the no-authorization path.
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

// tailOf returns the last n runes of out as a trimmed string — launchctl /
// osascript put the interesting error last, and the retry dialog has
// limited room.
func tailOf(out []byte, n int) string {
	s := strings.TrimSpace(string(out))
	if r := []rune(s); len(r) > n {
		s = "…" + string(r[len(r)-n:])
	}
	return s
}

// shellQuote wraps a value in single quotes, escaping embedded single quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
