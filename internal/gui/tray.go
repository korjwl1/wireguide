package gui

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"log/slog"
	"runtime"
	"strings"
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
// One icon per state. We use white-W icons unconditionally — macOS menu
// bar vibrancy makes white icons read correctly on both light and dark
// system themes (matching Apple's own Wi-Fi/battery/clock indicators).
// The previous design had separate dark-mode variants but assigned the
// same white-W to both, so we collapsed it to one.
var (
	trayOnIcon  []byte // white W + green dot
	trayOffIcon []byte // white W, no dot
)

func init() {
	white := color.NRGBA{255, 255, 255, 255}
	trayOnIcon = buildTrayOnIcon(white)
	trayOffIcon = buildTrayOffIcon(white)
}

// buildTrayOnIcon composites a W glyph (in wColor) with a green dot badge at
// the bottom-left. Returns a non-template PNG so the green dot keeps its colour.
// wColor should be black for light menu bars, white for dark menu bars.
// trimAndSquare finds the bounding box of non-transparent pixels, crops,
// then centers in a square canvas (max of width/height). Wails forces
// the tray icon to a thickness×thickness square, so providing a square
// image avoids distortion and controls the padding ourselves.
func trimAndSquare(src image.Image) *image.NRGBA {
	b := src.Bounds()
	minX, minY, maxX, maxY := b.Max.X, b.Max.Y, b.Min.X, b.Min.Y
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			_, _, _, a := src.At(x, y).RGBA()
			if a > 0 {
				if x < minX { minX = x }
				if y < minY { minY = y }
				if x > maxX { maxX = x }
				if y > maxY { maxY = y }
			}
		}
	}
	if maxX < minX {
		return image.NewNRGBA(image.Rect(0, 0, 1, 1))
	}
	cropW := maxX - minX + 1
	cropH := maxY - minY + 1
	// Square canvas: use the larger dimension
	side := cropW
	if cropH > side { side = cropH }
	dst := image.NewNRGBA(image.Rect(0, 0, side, side))
	offX := (side - cropW) / 2
	offY := (side - cropH) / 2
	for y := 0; y < cropH; y++ {
		for x := 0; x < cropW; x++ {
			dst.Set(x+offX, y+offY, src.At(x+minX, y+minY))
		}
	}
	return dst
}

func buildTrayOnIcon(wColor color.NRGBA) []byte {
	base, err := png.Decode(bytes.NewReader(icons.SystrayMacTemplate))
	if err != nil {
		slog.Warn("failed to decode base tray icon, using unmodified", "error", err)
		return icons.SystrayMacTemplate
	}

	trimmed := trimAndSquare(base)
	bounds := trimmed.Bounds()

	// Re-tint: replace black pixels with wColor, preserving alpha.
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			_, _, _, a := trimmed.At(x, y).RGBA()
			if a > 0 {
				trimmed.SetNRGBA(x, y, color.NRGBA{
					R: wColor.R,
					G: wColor.G,
					B: wColor.B,
					A: uint8(a >> 8),
				})
			}
		}
	}

	// Green badge: bottom-left corner.
	w, h := bounds.Dx(), bounds.Dy()
	cx, cy, r := w/5, h-h/5, h/8
	if r < 3 { r = 3 }
	green := color.NRGBA{52, 199, 89, 255} // macOS systemGreen
	for y := cy - r; y <= cy+r; y++ {
		for x := cx - r; x <= cx+r; x++ {
			dx, dy := x-cx, y-cy
			if dx*dx+dy*dy <= r*r && x >= 0 && y >= 0 && x < w && y < h {
				trimmed.SetNRGBA(x, y, green)
			}
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, trimmed); err != nil {
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

	trimmed := trimAndSquare(base)
	bounds := trimmed.Bounds()

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			_, _, _, a := trimmed.At(x, y).RGBA()
			if a > 0 {
				trimmed.SetNRGBA(x, y, color.NRGBA{
					R: wColor.R,
					G: wColor.G,
					B: wColor.B,
					A: uint8(a >> 8),
				})
			}
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, trimmed); err != nil {
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

	mu            sync.Mutex
	activeTunnels map[string]bool // cached from status events
	hasHandshake  map[string]bool // per-tunnel handshake status
	rebuildTimer  *time.Timer     // debounce timer for rebuildMenu
	// rebuildMu serialises rebuildMenu calls. The OnClick path needs to
	// know the rebuild has actually completed before it calls OpenMenu so
	// the menu can't open with stale items — a mutex is the simplest way
	// to make it block until it's that path's turn. Status-driven rebuilds
	// queue behind it harmlessly; rebuilds are sub-ms so the queue never
	// grows past one or two entries in practice.
	rebuildMu sync.Mutex
	// quitting flips to true the moment Quit is clicked. Both the
	// debounce AfterFunc and the rebuildMenu body short-circuit when
	// set, so a late-firing timer can't call SetMenu on a tray that
	// has already been Destroy()'d.
	quitting atomic.Bool
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

// initialBuild draws the menu once at startup, then registers an OnClick
// handler that rebuilds the menu before every open. The reactive
// status-driven rebuild (via setIconState) keeps the menu warm between
// events so opening it is instantaneous; this OnClick path guarantees the
// menu is fresh even when state changed in the small window between the
// last status event and the click. Without it, users occasionally saw a
// stale connection glyph for ~1s after a fast disconnect/connect cycle.
func (t *trayManager) initialBuild() {
	t.rebuildMenu()
	t.tray.OnClick(func() {
		// Run rebuild in a goroutine: OnClick fires on the AppKit main
		// thread, and rebuildMenu calls SetMenu which itself dispatches
		// to the main thread via Wails's InvokeSync — calling SetMenu
		// from main during an InvokeSync would deadlock.
		go func() {
			t.rebuildMenu()
			t.tray.OpenMenu()
		}()
	})
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
func (t *trayManager) setIconState(activeNames []string, handshakeMap map[string]bool) {
	newSet := make(map[string]bool, len(activeNames))
	for _, n := range activeNames {
		newSet[n] = true
	}

	t.mu.Lock()
	prev := t.activeTunnels
	prevHandshake := t.hasHandshake
	prevAnyConnected := len(prev) > 0
	t.activeTunnels = newSet
	t.hasHandshake = handshakeMap
	t.mu.Unlock()

	anyConnected := len(activeNames) > 0

	// Compute "did the active-set change" up front so we can both
	// (a) gate the SetIcon/SetTooltip cgo calls (they're cheap but
	// at 1Hz they add up) and (b) reuse the result for the menu
	// rebuild gate below.
	activeChanged := prevAnyConnected != anyConnected || len(prev) != len(newSet)
	if !activeChanged {
		for k := range prev {
			if !newSet[k] {
				activeChanged = true
				break
			}
		}
	}

	if activeChanged {
		if anyConnected {
			t.tray.SetIcon(trayOnIcon)
			tooltip := "WireGuide — " + strings.Join(activeNames, ", ")
			t.tray.SetTooltip(tooltip)
		} else {
			if runtime.GOOS == "darwin" {
				t.tray.SetIcon(trayOffIcon)
			}
			t.tray.SetTooltip("WireGuide")
		}
		if runtime.GOOS != "darwin" {
			if anyConnected {
				t.tray.SetLabel("WireGuide ●")
			} else {
				t.tray.SetLabel("WireGuide")
			}
		}
	} else if anyConnected {
		// Active names may have reordered without count changing.
		// Refresh tooltip only when names differ from last broadcast.
		newTooltip := "WireGuide — " + strings.Join(activeNames, ", ")
		t.tray.SetTooltip(newTooltip)
	}

	// Rebuild menu if active set changed OR if handshake state changed for
	// any active tunnel (◐ → ● flip without a connect/disconnect event).
	// Reuse activeChanged from the SetIcon gate above; only check
	// handshake transitions if the active-set itself didn't change.
	changed := activeChanged
	if !changed {
		for name := range newSet {
			if handshakeMap[name] != prevHandshake[name] {
				changed = true
				break
			}
		}
	}
	if changed {
		t.scheduleRebuild()
	}
}

// scheduleRebuild debounces rebuildMenu calls — multiple triggers within 100ms
// are coalesced into a single rebuild.
func (t *trayManager) scheduleRebuild() {
	if t.quitting.Load() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.rebuildTimer != nil {
		t.rebuildTimer.Stop()
	}
	t.rebuildTimer = time.AfterFunc(100*time.Millisecond, func() {
		if t.quitting.Load() {
			return
		}
		t.rebuildMenu()
	})
}

// rebuildMenu reconstructs the whole tray menu: tunnel list, Show Window,
// Quit. Uses ListTunnelsLocal (disk only, no IPC) + the cached activeTunnel
// for connected-state glyphs. Safe to invoke from any goroutine.
func (t *trayManager) rebuildMenu() {
	if t.quitting.Load() {
		return
	}
	t.rebuildMu.Lock()
	defer t.rebuildMu.Unlock()
	// Re-check quitting after acquiring the lock — Quit may have run
	// while a queued rebuild was waiting.
	if t.quitting.Load() {
		return
	}

	tunnels, err := t.svc.ListTunnelsLocal()
	if err != nil {
		slog.Debug("tray: list tunnels failed", "error", err)
	}

	// Snapshot both maps under a single lock so the active set we
	// render and the handshake bits we render are consistent — a
	// concurrent setIconState was previously able to swap activeTunnels
	// between the two reads, leading to "connected but no handshake
	// glyph" flickers.
	t.mu.Lock()
	activeSet := t.activeTunnels
	hsMap := t.hasHandshake
	t.mu.Unlock()

	m := t.app.NewMenu()
	m.Add("WireGuide").SetEnabled(false)
	m.AddSeparator()

	for _, tun := range tunnels {
		tun := tun // loop-var capture
		connected := activeSet[tun.Name]
		label := "○ " + tun.Name
		if connected && hsMap[tun.Name] {
			label = "● " + tun.Name // connected + handshake
		} else if connected {
			label = "◐ " + tun.Name // connected, no handshake
		}
		tunName := tun.Name
		m.Add(label).OnClick(func(ctx *application.Context) {
			t.mu.Lock()
			isActive := t.activeTunnels[tunName]
			t.mu.Unlock()
			if isActive {
				if err := t.svc.DisconnectTunnel(tunName); err != nil {
					slog.Warn("tray disconnect failed", "tunnel", tunName, "error", err)
				}
			} else {
				if err := t.svc.Connect(tunName); err != nil {
					slog.Warn("tray connect failed", "tunnel", tunName, "error", err)
				}
			}
		})
	}
	m.AddSeparator()
	m.Add("Show Window").OnClick(func(ctx *application.Context) {
		showDock()
	})
	m.AddSeparator()
	m.Add("Quit").OnClick(func(ctx *application.Context) {
		// Latch the quit flag BEFORE Destroy so any in-flight debounce
		// timer that fires between here and the AfterFunc cancel will
		// see it and bail. Then stop the timer explicitly to prevent
		// the goroutine from running at all in the common case.
		t.quitting.Store(true)
		t.mu.Lock()
		if t.rebuildTimer != nil {
			t.rebuildTimer.Stop()
			t.rebuildTimer = nil
		}
		t.mu.Unlock()
		t.doShutdown()
		t.tray.Destroy()
		t.app.Quit()
	})
	t.tray.SetMenu(m)
}
