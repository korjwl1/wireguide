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
	rebuilding    atomic.Bool     // guard against concurrent rebuildMenu calls
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
func (t *trayManager) setIconState(activeNames []string, handshakeMap map[string]bool) {
	newSet := make(map[string]bool, len(activeNames))
	for _, n := range activeNames {
		newSet[n] = true
	}

	t.mu.Lock()
	prev := t.activeTunnels
	prevHandshake := t.hasHandshake
	t.activeTunnels = newSet
	t.hasHandshake = handshakeMap
	t.mu.Unlock()

	anyConnected := len(activeNames) > 0

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

	// Rebuild menu if active set changed OR if handshake state changed for
	// any active tunnel (◐ → ● flip without a connect/disconnect event).
	changed := len(prev) != len(newSet)
	if !changed {
		for k := range prev {
			if !newSet[k] {
				changed = true
				break
			}
		}
	}
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
	activeSet := t.activeTunnels
	t.mu.Unlock()

	m := t.app.NewMenu()
	m.Add("WireGuide").SetEnabled(false)
	m.AddSeparator()

	hsMap := t.hasHandshake

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
		t.doShutdown()
		t.tray.Destroy()
		t.app.Quit()
	})
	t.tray.SetMenu(m)
}
