package gui

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	wgapp "github.com/korjwl1/wireguide/internal/app"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/icons"
)

// trayOnIcon is the template icon for "connected" state: the Wails default W
// with a small filled circle (●) in the bottom-left corner. Both icons use
// SetTemplateIcon so macOS auto-inverts for light/dark menu bar themes.
//
// Generated at init time by compositing a dot onto icons.SystrayMacTemplate.
var trayOnIcon []byte

func init() {
	trayOnIcon = buildTrayOnIcon()
}

// buildTrayOnIcon takes the Wails default 64x64 template W and draws a
// notification-style badge circle at the top-right corner, overlapping the W
// glyph — similar to Slack's red badge or iOS notification dots.
//
// Black-on-transparent is the macOS template icon format: the system uses the
// alpha channel as a mask and auto-tints for light/dark menu bar themes.
func buildTrayOnIcon() []byte {
	base, err := png.Decode(bytes.NewReader(icons.SystrayMacTemplate))
	if err != nil {
		slog.Warn("failed to decode base tray icon, using unmodified", "error", err)
		return icons.SystrayMacTemplate
	}
	bounds := base.Bounds()
	dst := image.NewNRGBA(bounds)
	draw.Draw(dst, bounds, base, bounds.Min, draw.Src)

	// Badge: filled circle at top-right, overlapping the W glyph.
	// For a 64x64 icon: center at (54, 10), radius 9 creates a prominent
	// badge that overlaps the top-right of the W, like a notification dot.
	cx, cy, r := 54, 10, 9
	black := color.NRGBA{0, 0, 0, 255}
	for y := cy - r; y <= cy+r; y++ {
		for x := cx - r; x <= cx+r; x++ {
			dx, dy := x-cx, y-cy
			if dx*dx+dy*dy <= r*r {
				dst.SetNRGBA(x, y, black)
			}
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, dst); err != nil {
		slog.Warn("failed to encode tray-on icon, using unmodified", "error", err)
		return icons.SystrayMacTemplate
	}
	return buf.Bytes()
}

// trayManager owns the system tray menu and its visual state.
//
// There are TWO update paths, intentionally separate:
//
//  1. setIconState(activeName) — cheap, called from the status event stream
//     every second. Only touches label + tooltip. NO IPC, NO disk I/O, so it
//     never blocks the event loop goroutine.
//
//  2. rebuildMenu() — expensive, rebuilds the full tunnel list in the menu.
//     Called only on user actions that change the list (add, delete, rename)
//     or on explicit refresh after connect/disconnect finishes.
//
// The previous design called the full rebuildMenu on every status event and
// did an IPC round-trip to the helper inside ListTunnels — that blocked the
// event stream, making the UI feel sluggish under a 1 Hz status broadcast.
type trayManager struct {
	app        *application.App
	tray       *application.SystemTray
	svc        *wgapp.TunnelService
	doShutdown func()

	mu           sync.Mutex
	activeTunnel string      // cached from status events, avoids MethodActiveName IPC
	rebuildTimer *time.Timer // debounce timer for rebuildMenu
	rebuilding   atomic.Bool // guard against concurrent rebuildMenu calls
}

func newTrayManager(app *application.App, tray *application.SystemTray, svc *wgapp.TunnelService, doShutdown func()) *trayManager {
	return &trayManager{
		app:        app,
		tray:       tray,
		svc:        svc,
		doShutdown: doShutdown,
	}
}

// initialBuild draws the menu once at startup.
func (t *trayManager) initialBuild() {
	t.rebuildMenu()
}

// setIconState swaps the tray ICON (not a text label) based on connection
// state, and updates the tooltip. Called from the status event stream, so
// it must stay O(1) — no IPC, no disk I/O.
//
//   disconnected → Wails's default template W (monochrome, auto-inverts)
//   connected    → coloured W with a green dot badge (non-template)
//
// Previously we used SetLabel("●") next to the template icon, but the user
// wanted the dot as a badge on the glyph itself, not as a neighbouring
// character. Two separate icon assets is the only way to achieve that on
// macOS's menu bar — template icons can't carry colour.
func (t *trayManager) setIconState(activeName string) {
	t.mu.Lock()
	prev := t.activeTunnel
	t.activeTunnel = activeName
	t.mu.Unlock()

	if activeName != "" {
		// Connected: W with a small dot badge. Both states use template icons
		// so macOS auto-inverts for light/dark menu bar themes.
		if runtime.GOOS == "darwin" {
			t.tray.SetTemplateIcon(trayOnIcon)
		}
		t.tray.SetTooltip("WireGuide — connected: " + activeName)
	} else {
		// Disconnected: plain W template icon.
		if runtime.GOOS == "darwin" {
			t.tray.SetTemplateIcon(icons.SystrayMacTemplate)
		}
		t.tray.SetTooltip("WireGuide")
	}

	// Non-macOS: fall back to a text label suffix since they don't
	// render template icons the same way. Harmless on macOS (label is
	// only shown alongside template icons, not coloured ones).
	if runtime.GOOS != "darwin" {
		if activeName != "" {
			t.tray.SetLabel("WireGuide ●")
		} else {
			t.tray.SetLabel("WireGuide")
		}
	}

	// When the active tunnel actually changes (not just a stats tick), we
	// also need to update the menu's glyphs. Debounce to 100ms so rapid
	// state transitions (e.g. disconnect+reconnect) coalesce into one rebuild.
	if prev != activeName {
		t.scheduleRebuild()
	}
}

// scheduleRebuild debounces rebuildMenu calls — multiple triggers within 100ms
// are coalesced into a single rebuild.
func (t *trayManager) scheduleRebuild() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.rebuildTimer != nil {
		t.rebuildTimer.Stop()
	}
	t.rebuildTimer = time.AfterFunc(100*time.Millisecond, t.rebuildMenu)
}

// rebuildMenu reconstructs the whole tray menu: tunnel list, Show Window,
// Quit. Uses ListTunnelsLocal (disk only, no IPC) + the cached activeTunnel
// for connected-state glyphs. Safe to invoke from any goroutine.
func (t *trayManager) rebuildMenu() {
	// Prevent concurrent rebuilds from overlapping AfterFunc timers.
	if !t.rebuilding.CompareAndSwap(false, true) {
		return
	}
	defer t.rebuilding.Store(false)

	tunnels, err := t.svc.ListTunnelsLocal()
	if err != nil {
		slog.Debug("tray: list tunnels failed", "error", err)
	}

	t.mu.Lock()
	activeName := t.activeTunnel
	t.mu.Unlock()

	m := t.app.NewMenu()
	m.Add("WireGuide").SetEnabled(false)
	m.AddSeparator()

	for _, tun := range tunnels {
		tun := tun // loop-var capture
		connected := tun.Name == activeName
		label := "○ " + tun.Name
		if connected {
			label = "● " + tun.Name
		}
		tunName := tun.Name
		m.Add(label).OnClick(func(ctx *application.Context) {
			// Query current state at click time to avoid stale closure capture.
			t.mu.Lock()
			isActive := t.activeTunnel == tunName
			t.mu.Unlock()
			if isActive {
				_ = t.svc.Disconnect()
			} else {
				_ = t.svc.Connect(tunName, false)
			}
		})
	}
	m.AddSeparator()
	m.Add("Show Window").OnClick(func(ctx *application.Context) { t.app.Show() })
	m.AddSeparator()
	m.Add("Quit").OnClick(func(ctx *application.Context) {
		t.doShutdown()
		t.app.Quit()
	})
	t.tray.SetMenu(m)
}
