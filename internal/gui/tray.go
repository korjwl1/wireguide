package gui

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"log/slog"
	"math"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	wgapp "github.com/korjwl1/wireguide/internal/app"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/icons"
	"golang.org/x/image/draw"
)

// Tray icon variants. macOS uses plain (non-template) coloured icons so
// the connected state can keep its GREEN dot badge — template images are
// alpha-only masks and cannot carry colour, which is why this design was
// chosen originally. Legibility across menu-bar appearances (issue #18:
// a fixed white W is invisible on a light menu bar) is handled by
// keeping one icon set per appearance and swapping the W glyph colour
// when the system theme changes (events.Mac.ApplicationDidChangeTheme →
// trayManager.setDarkMenuBar). We never call SetTemplateIcon, so the
// Wails v3 sticky-isTemplateIcon bug (once set, later SetIcon calls
// render monochrome) is never triggered.
//
// Known limit: this keys off the system light/dark theme. Extreme
// wallpaper-tinting edge cases where the menu bar deviates from the
// theme are not tracked — only template icons get that for free, and
// template would cost the green dot.
var (
	trayOnIconDark   []byte // white W + green dot (dark menu bar)
	trayOffIconDark  []byte // white W, no badge
	trayOnIconLight  []byte // black W + green dot (light menu bar)
	trayOffIconLight []byte // black W, no badge

	// Windows-only variants rendered from the full app icon (rounded
	// red tile + white W) so the system tray actually shows something
	// visible against light tray backgrounds. macOS keeps the
	// monochrome template above because the menu bar tints icons.
	trayOnIconWindows  []byte // app icon + green dot badge
	trayOffIconWindows []byte // app icon, no badge

	// customTrayIconPNG is the source the Windows builders read from. Set
	// by SetTrayIconPNG before gui.Run; init can't read it because Go
	// runs package init() at load time, well before main wires this up.
	customTrayIconPNG []byte
)

// SetTrayIconPNG hands the GUI package the raw bytes of the source app
// icon (a 1024×1024 RGBA PNG today). main.go embeds the file and calls
// this before invoking Run. The package keeps a copy so the Windows
// tray-icon builders can read it later. Calling with an empty slice
// disables the custom Windows tray icon (we fall back to the template).
func SetTrayIconPNG(b []byte) { customTrayIconPNG = b }

func init() {
	white := color.NRGBA{255, 255, 255, 255}
	black := color.NRGBA{0, 0, 0, 255}
	trayOnIconDark = buildTrayOnIcon(white)
	trayOffIconDark = buildTrayOffIcon(white)
	trayOnIconLight = buildTrayOnIcon(black)
	trayOffIconLight = buildTrayOffIcon(black)
}

// buildWindowsTrayIcons renders the rounded-red app icon at tray size
// for Windows, optionally with a green dot badge for the "connected"
// state. Called once from gui.Run after SetTrayIconPNG has populated
// the source bytes. Safe to call with an unset source — leaves the
// Windows variants nil and setIconState falls back to its existing
// macOS template path.
//
// We render at 32×32: Windows tray DPI scales icons to fit, and 32 is
// the next sane size up from 16 with enough room for anti-aliasing on
// the rounded corners and the W glyph. The source is downsampled with
// CatmullRom (high-quality bicubic) so the W stays crisp.
func buildWindowsTrayIcons() {
	if len(customTrayIconPNG) == 0 {
		return
	}
	src, err := png.Decode(bytes.NewReader(customTrayIconPNG))
	if err != nil {
		slog.Warn("tray: decode appicon for Windows tray failed", "error", err)
		return
	}

	const trayPx = 32
	// Corner radius chosen to mirror the inner red tile's curve so the
	// rounded outer silhouette and the inner red rounded square sit
	// concentric — that's the "일체감" (unified feel) the user asked for
	// instead of a hard white square framing the red tile.
	const trayCornerRadius = 7
	render := func(withBadge bool) []byte {
		dst := image.NewNRGBA(image.Rect(0, 0, trayPx, trayPx))
		draw.CatmullRom.Scale(dst, dst.Bounds(), src, src.Bounds(), draw.Over, nil)
		// Force-round the outer silhouette. Wails on Windows passes the
		// PNG straight to CreateIconFromResourceEx, which honours alpha,
		// so zeroing the alpha outside the rounded rect guarantees the
		// tray draws a rounded shape — independent of whether the
		// resized appicon happened to leave a few white-ish pixels in
		// the corners from CatmullRom's bleed at the tile edge.
		applyRoundedCorners(dst, trayCornerRadius)
		if withBadge {
			drawGreenBadge(dst)
		}
		var buf bytes.Buffer
		if err := png.Encode(&buf, dst); err != nil {
			slog.Warn("tray: encode Windows tray icon failed", "error", err)
			return nil
		}
		return buf.Bytes()
	}

	trayOffIconWindows = render(false)
	trayOnIconWindows = render(true)
}

// applyRoundedCorners zeros the alpha of pixels that lie outside a
// centered rounded rectangle of the given corner radius. A 1-pixel ring
// at the boundary is set to a fractional alpha proportional to its
// distance from the corner centre so the rounded edge is anti-aliased
// instead of stair-stepped.
//
// This runs AFTER the appicon is composited and is the last step before
// PNG encode — anything we want to keep visible must already be drawn.
func applyRoundedCorners(img *image.NRGBA, radius int) {
	if radius <= 0 {
		return
	}
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			// Identify which corner's circle this pixel belongs to.
			// The "straight edge" interior of the rounded rect needs no
			// mutation — bail early so the inner pixels are untouched.
			var cx, cy int
			switch {
			case x < radius && y < radius:
				cx, cy = radius, radius
			case x >= w-radius && y < radius:
				cx, cy = w-1-radius, radius
			case x < radius && y >= h-radius:
				cx, cy = radius, h-1-radius
			case x >= w-radius && y >= h-radius:
				cx, cy = w-1-radius, h-1-radius
			default:
				continue
			}
			dx, dy := float64(x-cx), float64(y-cy)
			d := math.Sqrt(dx*dx + dy*dy)
			r := float64(radius)
			switch {
			case d > r:
				img.SetNRGBA(x, y, color.NRGBA{})
			case d > r-1:
				// Anti-aliased edge: fade alpha from full at d=r-1 to
				// zero at d=r. Multiply by existing alpha so the
				// underlying icon's own translucency is preserved.
				c := img.NRGBAAt(x, y)
				c.A = uint8(float64(c.A) * (r - d))
				img.SetNRGBA(x, y, c)
			}
		}
	}
}

// drawGreenBadge paints a small green disc in the bottom-left corner of
// img, matching the macOS "connected" badge position. Anti-aliasing is
// a 1-pixel ring at the disc boundary so the badge doesn't look jagged
// at 32×32.
func drawGreenBadge(img *image.NRGBA) {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	// Badge geometry: 7px radius disc, centered ~6px from each edge.
	r := h / 5
	if r < 4 {
		r = 4
	}
	cx, cy := r+1, h-r-1
	green := color.NRGBA{52, 199, 89, 255} // macOS systemGreen
	for y := cy - r - 1; y <= cy+r+1; y++ {
		for x := cx - r - 1; x <= cx+r+1; x++ {
			if x < 0 || y < 0 || x >= w || y >= h {
				continue
			}
			dx, dy := x-cx, y-cy
			d2 := dx*dx + dy*dy
			r2 := r * r
			switch {
			case d2 <= r2:
				img.SetNRGBA(x, y, green)
			case d2 <= (r+1)*(r+1):
				// 1-pixel AA ring: blend by alpha proportional to
				// how far past the disc edge the pixel sits.
				img.SetNRGBA(x, y, color.NRGBA{green.R, green.G, green.B, 128})
			}
		}
	}
}

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

// buildTrayOnIcon composites a W glyph (in wColor) with a green dot badge
// at the bottom-left — the "connected" state. wColor should be white for
// dark menu bars and black for light menu bars; the dot stays green in
// both variants (the whole point of using non-template icons).
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
// disconnected state.
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
	// rebuildMu serialises rebuildMenu calls so two concurrent rebuilds
	// can't interleave their ListTunnelsLocal snapshot and SetMenu —
	// rebuilds are sub-ms so queued callers never wait meaningfully.
	rebuildMu sync.Mutex
	// quitting flips to true the moment Quit is clicked. Both the
	// debounce AfterFunc and the rebuildMenu body short-circuit when
	// set, so a late-firing timer can't call SetMenu on a tray that
	// has already been Destroy()'d.
	quitting atomic.Bool
	// darkMenuBar tracks the current system appearance (macOS only) so
	// setIconState can pick the icon variant whose W glyph contrasts
	// with the menu bar. Updated via setDarkMenuBar on theme changes.
	darkMenuBar atomic.Bool
}

// macIcons returns the on/off icon pair matching the current menu-bar
// appearance.
func (t *trayManager) macIcons() (on, off []byte) {
	if t.darkMenuBar.Load() {
		return trayOnIconDark, trayOffIconDark
	}
	return trayOnIconLight, trayOffIconLight
}

// setDarkMenuBar records the system appearance and immediately re-applies
// the icon for the current connection state, so a theme switch doesn't
// leave a low-contrast glyph up until the next connect/disconnect.
func (t *trayManager) setDarkMenuBar(dark bool) {
	if runtime.GOOS != "darwin" {
		return
	}
	t.darkMenuBar.Store(dark)
	t.mu.Lock()
	anyConnected := len(t.activeTunnels) > 0
	t.mu.Unlock()
	on, off := t.macIcons()
	if anyConnected {
		t.tray.SetIcon(on)
	} else {
		t.tray.SetIcon(off)
	}
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

// initialBuild draws the menu once at startup. No OnClick handler is
// registered — with no custom click handler, Wails lets AppKit run its
// native status-item menu tracking (the pre-click event monitor attaches
// the cached menu before the mouse-down is processed). The previous
// design intercepted the click and called OpenMenu, which synthesizes a
// fake NSEvent mouseDown — an unsupported trick that needed two clicks
// on some systems and stopped opening the menu at all on macOS 26
// (Tahoe reworked NSStatusItem internals). Menu freshness is covered by
// the status-driven scheduleRebuild path, and each item's OnClick reads
// live state at click time, so a ≤1s-stale glyph is the worst case.
func (t *trayManager) initialBuild() {
	t.rebuildMenu()
}

// setIconState swaps the tray ICON (not a text label) based on connection
// state, and updates the tooltip. Called from the status event stream, so
// it must stay O(1) — no IPC, no disk I/O.
//
//   disconnected → W glyph (white on dark menu bars, black on light)
//   connected    → same W with a green dot badge
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
		onIcon, offIcon := t.macIcons()
		if runtime.GOOS == "windows" && len(trayOnIconWindows) > 0 {
			// Use the rounded-red app-icon variants on Windows so the
			// tray icon actually stands out against a light system-tray
			// background and isn't framed by a white square.
			onIcon, offIcon = trayOnIconWindows, trayOffIconWindows
		}
		if anyConnected {
			t.tray.SetIcon(onIcon)
			tooltip := "WireGuide — " + strings.Join(activeNames, ", ")
			t.tray.SetTooltip(tooltip)
		} else {
			if runtime.GOOS == "darwin" || (runtime.GOOS == "windows" && len(offIcon) > 0) {
				t.tray.SetIcon(offIcon)
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
