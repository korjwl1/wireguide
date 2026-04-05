package gui

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// guiLogHandler chains to a stderr handler AND emits a Wails "log" event
// for every record. The frontend LogViewer subscribes to that event, so
// anything the GUI slogs (Wails bootstrap, helper lifecycle monitor,
// event bridge, etc) shows up in the viewer alongside the helper's
// forwarded records.
//
// Level is controlled by a shared slog.LevelVar. SetLogLevel writes to it
// and the change takes effect immediately for subsequent records. Info
// by default.
type guiLogHandler struct {
	levelVar *slog.LevelVar
	stderr   slog.Handler
	app      *application.App // may be nil before Wails finishes bootstrap

	mu    sync.Mutex
	attrs []slog.Attr
}

var guiLogLevel = new(slog.LevelVar)

// guiLogHandlerRef is shared so SetApp() can wire up the Wails app after
// bootstrap finishes. Until then, log records only hit stderr (and are
// lost to the viewer, which matches reality — the viewer isn't up yet).
var (
	guiLogRefMu sync.Mutex
	guiLogRef   *guiLogHandler
)

// installGUILogHandler builds the handler and installs it as slog default.
// Call before the first slog record you want captured.
func installGUILogHandler() {
	stderr := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: guiLogLevel})
	h := &guiLogHandler{
		levelVar: guiLogLevel,
		stderr:   stderr,
	}
	guiLogRefMu.Lock()
	guiLogRef = h
	guiLogRefMu.Unlock()
	slog.SetDefault(slog.New(h))
}

// bindAppToLogHandler tells the handler about the Wails app so subsequent
// records can be emitted as events. Called from gui.Run right after
// application.New.
func bindAppToLogHandler(app *application.App) {
	guiLogRefMu.Lock()
	defer guiLogRefMu.Unlock()
	if guiLogRef != nil {
		guiLogRef.mu.Lock()
		guiLogRef.app = app
		guiLogRef.mu.Unlock()
	}
}

// setGUILogLevel updates the threshold for both stderr and the Wails
// broadcast. Mirrors the helper-side SetLogLevel behaviour.
func setGUILogLevel(level string) {
	guiLogLevel.Set(parseGUILevel(level))
}

func parseGUILevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func (h *guiLogHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.levelVar.Level()
}

func (h *guiLogHandler) Handle(ctx context.Context, r slog.Record) error {
	_ = h.stderr.Handle(ctx, r)

	var b strings.Builder
	b.WriteString(r.Message)
	h.mu.Lock()
	for _, a := range h.attrs {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Any())
	}
	app := h.app
	h.mu.Unlock()
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Any())
		return true
	})

	if app != nil {
		app.Event.Emit("log", ipc.LogEntry{
			Time:    r.Time.UTC().Format(time.RFC3339Nano),
			Level:   strings.ToLower(r.Level.String()),
			Source:  "gui",
			Message: b.String(),
		})
	}
	return nil
}

func (h *guiLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.mu.Lock()
	combined := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	combined = append(combined, h.attrs...)
	combined = append(combined, attrs...)
	app := h.app
	h.mu.Unlock()
	return &guiLogHandler{
		levelVar: h.levelVar,
		stderr:   h.stderr.WithAttrs(attrs),
		app:      app,
		attrs:    combined,
	}
}

func (h *guiLogHandler) WithGroup(name string) slog.Handler {
	h.mu.Lock()
	app := h.app
	h.mu.Unlock()
	return &guiLogHandler{
		levelVar: h.levelVar,
		stderr:   h.stderr.WithGroup(name),
		app:      app,
		attrs:    h.attrs,
	}
}
