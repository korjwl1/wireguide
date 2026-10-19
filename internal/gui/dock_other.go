//go:build !darwin

package gui

import (
	"runtime"
	"sync"

	"github.com/wailsapp/wails/v3/pkg/application"
)

var dockWindow *application.WebviewWindow

// showDock is reachable concurrently on Linux — StatusNotifier Activate and
// dbusmenu events each arrive on their own godbus goroutine, and Wails runs
// menu callbacks on fresh goroutines. The frameless toggle below must not
// interleave between two callers or the window can map undecorated with no
// recovery (GTK caches the decorated hint), so the whole show is serialized.
var showDockMu sync.Mutex

// showDock brings back the main window after close-to-tray. Unlike macOS
// there is no dock icon / activation policy to juggle (and no async retry
// dance) — un-minimise + Show + Focus on the window is the whole job.
// Restore comes first: Show() alone does not un-minimise on Windows, so a
// window hidden while minimised would otherwise reappear only in the
// taskbar, still collapsed.
func showDock() {
	showDockMu.Lock()
	defer showDockMu.Unlock()
	if dockWindow == nil || appQuitting.Load() {
		return
	}
	restoreMainWindow(dockWindow, runtime.GOOS == "linux")
}

// hideDock only exists to hide the macOS dock icon — the window itself is
// already hidden by the WindowClosing hook, so there is nothing to do here.
func hideDock() {}
