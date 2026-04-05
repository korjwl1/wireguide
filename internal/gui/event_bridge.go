package gui

import (
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// eventBridge forwards IPC notifications from the helper to Wails events the
// frontend subscribes to. It also exposes `Resubscribe()` so the helper
// lifecycle monitor can re-establish the event stream after a helper restart.
type eventBridge struct {
	app     *application.App
	clients *ipc.ClientHolder
	// onStatusChange is the cheap hook called for every status event — it
	// updates the tray icon's label/tooltip without any IPC or disk work so
	// the event loop goroutine never blocks on it.
	onStatusChange func(activeName string)

	mu           sync.Mutex
	subscribedTo *ipc.Client // tracks which client we're currently subscribed on
}

func newEventBridge(app *application.App, clients *ipc.ClientHolder, onStatusChange func(activeName string)) *eventBridge {
	return &eventBridge{
		app:            app,
		clients:        clients,
		onStatusChange: onStatusChange,
	}
}

// start attaches the event subscription to the current client.
func (b *eventBridge) start() {
	b.resubscribe()
}

// Resubscribe re-attaches after a helper restart. Called by the health monitor
// right after it swaps the client in the holder.
func (b *eventBridge) Resubscribe() {
	b.resubscribe()
	// Let the frontend know that state is now fresh — it should re-fetch the
	// tunnel list and status since the helper lost any in-memory state.
	b.app.Event.Emit("helper_reset", struct{}{})
}

func (b *eventBridge) resubscribe() {
	c := b.clients.Get()
	if c == nil {
		return
	}

	b.mu.Lock()
	if b.subscribedTo == c {
		b.mu.Unlock()
		return // already subscribed on this exact client
	}
	b.subscribedTo = c
	b.mu.Unlock()

	if err := c.Subscribe(b.handleEvent); err != nil {
		slog.Warn("event subscription failed", "error", err)
	}
}

func (b *eventBridge) handleEvent(method string, params json.RawMessage) {
	switch method {
	case ipc.EventStatus:
		var status domain.ConnectionStatus
		if json.Unmarshal(params, &status) == nil {
			b.app.Event.Emit("status", status)
			if b.onStatusChange != nil {
				// Derive active tunnel name directly from the event payload —
				// no IPC round-trip, no disk read, never blocks the event loop.
				activeName := ""
				if status.State == domain.StateConnected {
					activeName = status.TunnelName
				}
				b.onStatusChange(activeName)
			}
		}
	case ipc.EventReconnect:
		var dto ipc.ReconnectStateDTO
		if json.Unmarshal(params, &dto) == nil {
			b.app.Event.Emit("reconnect", ReconnectEvent{
				Reconnecting: dto.Reconnecting,
				Attempt:      dto.Attempt,
				MaxAttempts:  dto.MaxAttempts,
			})
		}
	case ipc.EventLog:
		// Helper-side slog record: forward as-is to the frontend. The
		// LogViewer subscribes to the "log" Wails event and appends each
		// entry. Without this bridge the helper's stderr output is swallowed
		// by osascript during spawn and the viewer stays empty forever.
		var entry ipc.LogEntry
		if json.Unmarshal(params, &entry) == nil {
			b.app.Event.Emit("log", entry)
		}
	}
}
