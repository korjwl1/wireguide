package gui

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"log/slog"
	"math"
	"sync"

	"github.com/korjwl1/wireguide/internal/domain"
	"golang.org/x/image/draw"
)

// ActiveTunnels also contains in-progress work. A green connection indicator
// requires Connected; the history/UI still receive the complete original DTO.
func connectedStatusIndicators(status domain.ConnectionStatus) ([]string, map[string]bool) {
	rows := status.Tunnels
	if len(rows) == 0 {
		rows = []domain.ConnectionStatus{status}
	}
	var names []string
	handshakes := make(map[string]bool)
	for _, row := range rows {
		if row.State == domain.StateConnected && row.TunnelName != "" {
			names = append(names, row.TunnelName)
			handshakes[row.TunnelName] = row.LastHandshake != ""
		}
	}
	return names, handshakes
}

type connectionIconImages struct {
	base, connected []byte
}

func buildConnectionIconImages(source []byte) (connectionIconImages, error) {
	var result connectionIconImages
	src, err := png.Decode(bytes.NewReader(source))
	if err != nil {
		return result, err
	}
	img := image.NewNRGBA(image.Rect(0, 0, 256, 256))
	draw.CatmullRom.Scale(img, img.Bounds(), src, src.Bounds(), draw.Src, nil)
	// Match the rounded alpha mask of the packaged Windows icon and tray.
	applyRoundedCorners(img, 56)
	encode := func(img image.Image) ([]byte, error) {
		var buf bytes.Buffer
		err := png.Encode(&buf, img)
		return buf.Bytes(), err
	}
	if result.base, err = encode(img); err != nil {
		return result, err
	}
	paintConnectionDot(img, 44, 212, 26, 3)
	if result.connected, err = encode(img); err != nil {
		return result, err
	}
	return result, nil
}

// The outline keeps the green visible against the red tile and either shell
// background. Coverage blending preserves the source outside the dot.
func paintConnectionDot(img *image.NRGBA, cx, cy, radius, outline float64) {
	// Reuse the brush and color storage across pixels; draw consumes both
	// synchronously, so no per-pixel image/interface allocation is needed.
	var c color.NRGBA
	brush := image.NewUniform(&c)
	outer := radius + outline
	for y := int(cy - outer - 1); y <= int(cy+outer+1); y++ {
		for x := int(cx - outer - 1); x <= int(cx+outer+1); x++ {
			if !image.Pt(x, y).In(img.Bounds()) {
				continue
			}
			distance := math.Hypot(float64(x)+0.5-cx, float64(y)+0.5-cy)
			coverage := min(1, max(0, outer+0.5-distance))
			if coverage == 0 {
				continue
			}
			green := min(1, max(0, radius+0.5-distance))
			c = color.NRGBA{
				R: uint8(255*(1-green) + 52*green),
				G: uint8(255*(1-green) + 199*green),
				B: uint8(255*(1-green) + 89*green),
				A: uint8(255 * coverage),
			}
			draw.Draw(img, image.Rect(x, y, x+1, y+1), brush, image.Point{}, draw.Over)
		}
	}
}

// connectionIcon coalesces status updates onto the GUI thread. Startup,
// shell recreation and shutdown share the same latest-state model; status
// callbacks never decode images, touch files, or call shell APIs inline.
type connectionIcon struct {
	mu         sync.Mutex
	dispatch   func(func())
	apply      func(bool) error
	wanted     bool
	applied    bool
	hasApplied bool
	ready      bool
	queued     bool
	closed     bool
	revision   uint64
}

func newConnectionIcon(dispatch func(func()), apply func(bool) error) *connectionIcon {
	return &connectionIcon{dispatch: dispatch, apply: apply}
}

func (i *connectionIcon) SetConnected(connected bool) {
	i.update(func() { i.wanted = connected })
}

func (i *connectionIcon) Ready() { i.update(func() { i.ready = true }) }

func (i *connectionIcon) Refresh() {
	i.update(func() { i.revision++; i.hasApplied = false })
}

func (i *connectionIcon) Close() {
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return
	}
	i.closed = true
	ready := i.ready
	i.mu.Unlock()
	if ready {
		i.dispatch(func() {
			if err := i.apply(false); err != nil {
				slog.Debug("cannot reset application icon during shutdown", "error", err)
			}
		})
	}
}

func (i *connectionIcon) update(change func()) {
	i.mu.Lock()
	change()
	schedule := i.scheduleLocked()
	i.mu.Unlock()
	if schedule {
		i.dispatch(i.flush)
	}
}

func (i *connectionIcon) scheduleLocked() bool {
	if i.closed || !i.ready || i.queued || (i.hasApplied && i.applied == i.wanted) {
		return false
	}
	i.queued = true
	return true
}

func (i *connectionIcon) flush() {
	i.mu.Lock()
	if i.closed {
		i.queued = false
		i.mu.Unlock()
		return
	}
	wanted, revision := i.wanted, i.revision
	i.mu.Unlock()
	err := i.apply(wanted)
	i.mu.Lock()
	i.queued = false
	// Do not retry failed shell calls on the 1 Hz status stream. A window
	// show or shell-recreation event explicitly requests another attempt.
	i.applied, i.hasApplied = wanted, revision == i.revision
	schedule := i.scheduleLocked()
	i.mu.Unlock()
	if err != nil {
		slog.Warn("cannot update application connection icon", "error", err)
	}
	if schedule {
		i.dispatch(i.flush)
	}
}
