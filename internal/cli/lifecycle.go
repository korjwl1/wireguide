package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/sysexec"
)

// macBundleID must match CFBundleIdentifier in build/darwin/Info.plist.
// `open -b` uses it to find an installed WireGuide.app wherever it lives,
// which beats guessing at /Applications.
const macBundleID = "com.korjwl1.wireguide"

// startTimeout bounds how long `ctl start` waits for the helper socket to
// come up. Generous because the very first launch (or the first after the
// GUI stopped the helper) shows a macOS admin-password dialog, and the
// socket only appears once the user has typed it.
const startTimeout = 2 * time.Minute

// cmdStart launches the WireGuide app and waits until the helper is
// reachable.
//
// Deliberately the ONLY command that starts anything. `connect`, `status`
// and friends fail with "is the app running?" instead of silently starting
// a VPN stack behind the user's back — the same contract the docker CLI has
// with dockerd. Starting is an explicit act because on macOS it costs an
// admin-password prompt, and because a running WireGuide is exactly what
// the helper treats as consent to apply automation rules.
func cmdStart(_ []string) int {
	// Already up? Then this is a no-op, not an error — `ctl start` should
	// be safe to put at the top of a script.
	if c, err := dialHelper(); err == nil {
		c.Close()
		fmt.Println("WireGuide is already running")
		return 0
	}

	if err := launchApp(); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}

	fmt.Println("starting WireGuide…")
	if runtime.GOOS == "darwin" {
		fmt.Println("(macOS may ask for your administrator password to start the VPN helper)")
	}

	deadline := time.Now().Add(startTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		if c, err := dialHelper(); err == nil {
			c.Close()
			fmt.Println("WireGuide is running")
			return 0
		}
	}
	fmt.Fprintf(os.Stderr,
		"start: the app was launched but its helper did not come up within %s\n", startTimeout)
	return 1
}

// cmdStop asks the running app to quit — GUI and helper together.
//
// The request goes to the helper rather than to the GUI directly, because
// the helper is the process the CLI can already reach on every platform.
// It broadcasts EventQuit to the GUI (which then runs its own quit path and
// stops the helper on the way out), or shuts itself down when no GUI is
// attached. That keeps `stop` free of per-OS "terminate that application"
// machinery.
func cmdStop(_ []string) int {
	c, err := dialHelper()
	if err != nil {
		// Nothing to stop is success: `ctl stop` states a desired end
		// state, and we're already in it.
		fmt.Println("WireGuide is not running")
		return 0
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var resp ipc.RequestQuitResponse
	if err := c.CallWithContext(ctx, ipc.MethodRequestQuit, nil, &resp); err != nil {
		fmt.Fprintln(os.Stderr, "stop:", err)
		if strings.Contains(err.Error(), "method not found") {
			fmt.Fprintln(os.Stderr,
				"this helper predates 'ctl stop' — quit WireGuide from its tray icon, or restart the app once to upgrade the helper.")
		}
		return 1
	}
	if resp.NotifiedGUI {
		fmt.Println("stopping WireGuide…")
	} else {
		fmt.Println("no app was running; stopped the leftover helper")
	}

	// Confirm it actually went away rather than reporting success on a
	// request that was merely accepted.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		probe, perr := dialHelper()
		if perr != nil {
			fmt.Println("WireGuide stopped")
			return 0
		}
		probe.Close()
	}
	fmt.Fprintln(os.Stderr, "stop: WireGuide did not shut down within 20s")
	return 1
}

// launchApp starts the GUI, detached from this process so the CLI can exit
// without taking the app with it.
func launchApp() error {
	switch runtime.GOOS {
	case "darwin":
		// `open` returns as soon as the app is launched and does not tie
		// the app's lifetime to ours. Prefer the bundle ID so an app
		// installed anywhere (/Applications, ~/Applications, a dev
		// build that's been run once) is found via LaunchServices.
		if err := exec.Command("open", "-b", macBundleID).Run(); err == nil {
			return nil
		}
		// Not registered with LaunchServices (common for a freshly built
		// bundle that has never been opened) — fall back to the .app
		// enclosing our own binary, then to the bare executable.
		if app := enclosingAppBundle(); app != "" {
			if err := exec.Command("open", app).Run(); err == nil {
				return nil
			}
		}
		return spawnSelfDetached()
	default:
		// Linux and Windows: the GUI is this same binary invoked with no
		// arguments (see main.go — only `ctl` routes into the CLI), so
		// re-exec ourselves rather than hunting for a launcher.
		return spawnSelfDetached()
	}
}

// enclosingAppBundle returns the path of the .app bundle containing this
// executable, or "" when we're not inside one (dev build, bare binary).
func enclosingAppBundle() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	// …/WireGuide.app/Contents/MacOS/wireguide → …/WireGuide.app
	dir := filepath.Dir(exe)
	for i := 0; i < 3 && dir != "/" && dir != "."; i++ {
		if strings.HasSuffix(dir, ".app") {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	return ""
}

// spawnSelfDetached re-executes this binary with no arguments (which starts
// the GUI) and detaches it, so the app outlives the CLI process.
func spawnSelfDetached() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate the WireGuide executable: %w", err)
	}
	cmd := exec.Command(exe)
	// Detach stdio: inheriting the terminal would keep the app tied to the
	// shell and leak its logs into the user's session.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	sysexec.Detach(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot launch the WireGuide app: %w", err)
	}
	// Release the child so it isn't reaped when the CLI exits.
	return cmd.Process.Release()
}
