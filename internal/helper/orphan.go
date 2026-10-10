package helper

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
)

// Paths of the macOS LaunchDaemon install (see internal/elevate).
const (
	orphanDaemonLabel  = "com.wireguide.helper"
	orphanDaemonPlist  = "/Library/LaunchDaemons/" + orphanDaemonLabel + ".plist"
	orphanDaemonBinary = "/Library/PrivilegedHelperTools/" + orphanDaemonLabel
)

// orphanRecheckDelay separates the two existence checks so an in-place app
// update (old bundle briefly missing while it is swapped) is not mistaken
// for a removal.
const orphanRecheckDelay = 2 * time.Second

// orphanOps are the side effects of the self-uninstall, behind a seam so the
// decision logic is testable without touching the system.
type orphanOps struct {
	exists func(path string) bool
	sleep  func(time.Duration)
	remove func(path string) error
	// bootout unloads the LaunchDaemon job. It kills this process, so it
	// runs last.
	bootout func() error
	// recover undoes live state (pf rules, DNS overrides) left by a previous
	// helper run. It runs after the orphan is confirmed and BEFORE any file
	// is removed: once the binary is gone nothing could clean that up.
	recover func()
}

func defaultOrphanOps() orphanOps {
	return orphanOps{
		exists: func(p string) bool {
			_, err := os.Stat(p)
			// Only a definite "not there" counts; any other error (e.g.
			// permissions) is treated as present so we never uninstall on doubt.
			return err == nil || !os.IsNotExist(err)
		},
		sleep:  time.Sleep,
		remove: os.Remove,
		bootout: func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return exec.CommandContext(ctx, "launchctl", "bootout", "system/"+orphanDaemonLabel).Run()
		},
	}
}

// HandleOrphanedInstall implements the --app-bundle check. When the app that
// installed this socket-activated LaunchDaemon no longer exists, the helper
// removes its own install and returns true: the caller must exit 0 without
// serving. It returns false (and does nothing) when appBundle is empty, the
// platform is not macOS, the process is not root, or the bundle exists.
//
// recoverFn is the crash-recovery sequence; it is invoked before the install
// is removed (and only when the helper is going to uninstall itself).
func HandleOrphanedInstall(appBundle string, recoverFn func()) bool {
	if runtime.GOOS != "darwin" || os.Geteuid() != 0 {
		return false
	}
	ops := defaultOrphanOps()
	ops.recover = recoverFn
	return handleOrphanedInstall(appBundle, ops)
}

func handleOrphanedInstall(appBundle string, ops orphanOps) bool {
	if appBundle == "" {
		return false
	}
	if !filepath.IsAbs(appBundle) {
		slog.Warn("ignoring non-absolute --app-bundle", "path", appBundle)
		return false
	}
	if ops.exists(appBundle) {
		return false
	}
	// Possibly mid-update: confirm after a pause.
	ops.sleep(orphanRecheckDelay)
	if ops.exists(appBundle) {
		return false
	}
	slog.Warn("the app that installed this helper is gone; uninstalling the helper",
		"app_bundle", appBundle)
	if ops.recover != nil {
		ops.recover()
	}
	for _, p := range []string{orphanDaemonPlist, orphanDaemonBinary, ipc.DarwinSocketPath} {
		if err := ops.remove(p); err != nil && !os.IsNotExist(err) {
			slog.Warn("orphan cleanup: remove failed", "path", p, "error", err)
		}
	}
	// Last: unloading the job terminates this process.
	if err := ops.bootout(); err != nil {
		slog.Warn("orphan cleanup: launchctl bootout failed", "error", err)
	}
	return true
}
