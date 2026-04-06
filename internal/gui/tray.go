package gui

import (
	"bytes"
	"image"
	"image/color"
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

// Tray icon variants. We always use SetIcon (non-template) to avoid a
// Wails v3 bug where SetTemplateIcon sets isTemplateIcon=true on the
// macosSystemTray struct, and the subsequent SetIcon never clears it —
// causing all future icons to be rendered monochrome by macOS.
//
// Two colour variants per state because non-template icons don't
// auto-invert — black W for light menu bars, white W for dark.
var (
	trayOnIcon      []byte // black W + green dot (light menu bar)
	trayOnIconDark  []byte // white W + green dot (dark menu bar)
	trayOffIcon     []byte // black W, no dot (light menu bar)
	trayOffIconDark []byte // white W, no dot (dark menu bar)
)

func init() {
	// macOS menu bar always has a semi-dark vibrancy background, so white
	// icons look correct in both light and dark system themes — matching
	// Apple's own Wi-Fi, battery, clock icons which are always white.
	// We use white W for all themes. The green dot is the only colour.
	white := color.NRGBA{255, 255, 255, 255}
	trayOnIcon = buildTrayOnIcon(white)
	trayOnIconDark = trayOnIcon // same — white W works everywhere
	trayOffIcon = buildTrayOffIcon(white)
	trayOffIconDark = trayOffIcon
}

// buildTrayOnIcon composites a W glyph (in wColor) with a green dot badge at
// the bottom-left. Returns a non-template PNG so the green dot keeps its colour.
// wColor should be black for light menu bars, white for dark menu bars.
func buildTrayOnIcon(wColor color.NRGBA) []byte {
	base, err := png.Decode(bytes.NewReader(icons.SystrayMacTemplate))
	if err != nil {
		slog.Warn("failed to decode base tray icon, using unmodified", "error", err)
		return icons.SystrayMacTemplate
	}
	bounds := base.Bounds()
	dst := image.NewNRGBA(bounds)

	// The template icon has black pixels with varying alpha. Re-tint each
	// pixel to wColor while preserving its alpha — this turns the black W
	// into a white W (for dark mode) or keeps it black (for light mode).
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			_, _, _, a := base.At(x, y).RGBA()
			if a > 0 {
				dst.SetNRGBA(x, y, color.NRGBA{
					R: wColor.R,
					G: wColor.G,
					B: wColor.B,
					A: uint8(a >> 8),
				})
			}
		}
	}

	// Green badge: filled circle overlapping the W's left leg.
	// The W occupies roughly x=15-49, y=16-48 in the 64x64 icon.
	// Placing the dot at (20, 48) with radius 8 centers it on the left
	// leg's bottom, overlapping the glyph like a notification badge.
	cx, cy, r := 20, 48, 8
	green := color.NRGBA{52, 199, 89, 255} // macOS systemGreen
	for y := cy - r; y <= cy+r; y++ {
		for x := cx - r; x <= cx+r; x++ {
			dx, dy := x-cx, y-cy
			if dx*dx+dy*dy <= r*r {
				dst.SetNRGBA(x, y, green)
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

// buildTrayOffIcon renders the W glyph in wColor with no badge — the
// disconnected-state equivalent of the template icon, but as a plain
// (non-template) PNG so we never need SetTemplateIcon.
func buildTrayOffIcon(wColor color.NRGBA) []byte {
	base, err := png.Decode(bytes.NewReader(icons.SystrayMacTemplate))
	if err != nil {
		slog.Warn("failed to decode base tray icon, using unmodified", "error", err)
		return icons.SystrayMacTemplate
	}
	bounds := base.Bounds()
	dst := image.NewNRGBA(bounds)

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			_, _, _, a := base.At(x, y).RGBA()
			if a > 0 {
				dst.SetNRGBA(x, y, color.NRGBA{
					R: wColor.R,
					G: wColor.G,
					B: wColor.B,
					A: uint8(a >> 8),
				})
			}
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, dst); err != nil {
		slog.Warn("failed to encode tray-off icon, using unmodified", "error", err)
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
	win        *application.WebviewWindow
	tray       *application.SystemTray
	svc        *wgapp.TunnelService
	doShutdown func()

	mu           sync.Mutex
	activeTunnel string      // cached from status events, avoids MethodActiveName IPC
	rebuildTimer *time.Timer // debounce timer for rebuildMenu
	rebuilding   atomic.Bool // guard against concurrent rebuildMenu calls
}

func newTrayManager(app *application.App, win *application.WebviewWindow, tray *application.SystemTray, svc *wgapp.TunnelService, doShutdown func()) *trayManager {
	return &trayManager{
		app:        app,
		win:        win,
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
		t.tray.SetIcon(trayOnIcon)
		t.tray.SetTooltip("WireGuide — connected: " + activeName)
	} else {
		if runtime.GOOS == "darwin" {
			t.tray.SetIcon(trayOffIcon)
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
				_ = t.svc.Connect(tunName)
			}
		})
	}
	m.AddSeparator()
	m.Add("Show Window").OnClick(func(ctx *application.Context) {
		showDock()
	})
	m.AddSeparator()
	m.Add("Quit").OnClick(func(ctx *application.Context) {
		t.doShutdown()
		t.app.Quit()
	})
	t.tray.SetMenu(m)
}
