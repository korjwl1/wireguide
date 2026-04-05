package helper

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
)

// broadcastHandler is an slog.Handler that chains to a stderr handler AND
// broadcasts every log record to any IPC subscriber. This lets the GUI's
// LogViewer see what the helper is doing in real time — previously all
// helper logs went to stderr which is captured-and-discarded when the
// helper is spawned via osascript, so the viewer was effectively blank.
//
// Level is controlled by a shared slog.LevelVar that Helper.SetLogLevel
// mutates at runtime. Both the stderr path and the broadcast path honour
// the same level, so "change to DEBUG" in Settings immediately shows
// debug records in the viewer.
type broadcastHandler struct {
	levelVar *slog.LevelVar
	stderr   slog.Handler

	// broadcast is the helper's broadcaster — we look it up lazily via
	// getBroadcaster because the handler is installed in slog.SetDefault
	// BEFORE the Helper struct is fully constructed.
	getBroadcaster func() func(method string, params interface{})

	// attrs holds WithAttrs/WithGroup state so Handle can render them.
	mu    sync.Mutex
	attrs []slog.Attr
	group string
}

func newBroadcastHandler(levelVar *slog.LevelVar, getBroadcaster func() func(string, interface{})) *broadcastHandler {
	stderr := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: levelVar,
	})
	return &broadcastHandler{
		levelVar:       levelVar,
		stderr:         stderr,
		getBroadcaster: getBroadcaster,
	}
}

func (h *broadcastHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.levelVar.Level()
}

func (h *broadcastHandler) Handle(ctx context.Context, r slog.Record) error {
	// Always write to stderr (for tail -f helper.log in dev, for apple
	// unified log ingestion in prod).
	_ = h.stderr.Handle(ctx, r)

	// Render the same record as a single flat string for the viewer.
	var b strings.Builder
	b.WriteString(r.Message)
	// Append WithAttrs-captured attrs first, then record-local attrs.
	h.mu.Lock()
	for _, a := range h.attrs {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Any())
	}
	h.mu.Unlock()
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Any())
		return true
	})

	entry := ipc.LogEntry{
		Time:    r.Time.UTC().Format(time.RFC3339Nano),
		Level:   strings.ToLower(r.Level.String()),
		Source:  "helper",
		Message: b.String(),
	}

	if bc := h.getBroadcaster(); bc != nil {
		bc(ipc.EventLog, entry)
	}
	return nil
}

func (h *broadcastHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.mu.Lock()
	combined := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	combined = append(combined, h.attrs...)
	combined = append(combined, attrs...)
	h.mu.Unlock()
	return &broadcastHandler{
		levelVar:       h.levelVar,
		stderr:         h.stderr.WithAttrs(attrs),
		getBroadcaster: h.getBroadcaster,
		attrs:          combined,
		group:          h.group,
	}
}

func (h *broadcastHandler) WithGroup(name string) slog.Handler {
	return &broadcastHandler{
		levelVar:       h.levelVar,
		stderr:         h.stderr.WithGroup(name),
		getBroadcaster: h.getBroadcaster,
		attrs:          h.attrs,
		group:          name,
	}
}

// parseLevel maps a user-facing string ("debug", "info", ...) to slog.Level.
// Unknown strings default to Info.
func parseLevel(s string) slog.Level {
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
