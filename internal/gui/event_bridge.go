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
	onStatusChange func(activeNames []string, handshakeMap map[string]bool)
	// onReconcileHistory is called on every status event with the active
	// tunnel set + per-tunnel rx/tx so the history store can record sessions
	// that were started or ended by the helper itself (auto-reconnect on
	// wake, wifi rules, health-check recovery). nil when the bridge runs
	// without a history store.
	onReconcileHistory func(activeNames []string, rx, tx map[string]int64, reason string)

	mu           sync.Mutex
	subscribedTo *ipc.Client // tracks which client we're currently subscribed on
}

func newEventBridge(
	app *application.App,
	clients *ipc.ClientHolder,
	onStatusChange func(activeNames []string, handshakeMap map[string]bool),
	onReconcileHistory func(activeNames []string, rx, tx map[string]int64, reason string),
) *eventBridge {
	return &eventBridge{
		app:                app,
		clients:            clients,
		onStatusChange:     onStatusChange,
		onReconcileHistory: onReconcileHistory,
	}
}

// start attaches the event subscription to the current client.
func (b *eventBridge) start() {
	b.resubscribe()
}

// Resubscribe re-attaches after a helper restart. Called by the health monitor
// right after it swaps the client in the holder.
//
// Race safety: the old goroutine (from the previous Subscribe call) will
// terminate on its own when the old connection's read loop returns an error
// (the dead socket gets closed). The new Subscribe call starts a fresh
// goroutine on the new client. There is no shared mutable state between the
// two goroutines — the subscribedTo guard prevents double-subscribing on the
// same client, and the old goroutine's callback becomes a no-op once its
// connection is gone.
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
		// Reset subscribedTo so a subsequent Resubscribe can retry.
		b.mu.Lock()
		b.subscribedTo = nil
		b.mu.Unlock()
	}
}

func (b *eventBridge) handleEvent(method string, params json.RawMessage) {
	switch method {
	case ipc.EventStatus:
		var status domain.ConnectionStatus
		if err := json.Unmarshal(params, &status); err != nil {
			slog.Debug("event bridge: unmarshal status failed", "error", err)
		} else {
			b.app.Event.Emit("status", status)
			if b.onStatusChange != nil {
				hsMap := make(map[string]bool)
				for _, ts := range status.Tunnels {
					hsMap[ts.TunnelName] = ts.LastHandshake != ""
				}
				if status.TunnelName != "" {
					hsMap[status.TunnelName] = status.LastHandshake != ""
				}
				b.onStatusChange(status.ActiveTunnels, hsMap)
			}
			if b.onReconcileHistory != nil {
				rx := make(map[string]int64, len(status.Tunnels)+1)
				tx := make(map[string]int64, len(status.Tunnels)+1)
				for _, ts := range status.Tunnels {
					rx[ts.TunnelName] = ts.RxBytes
					tx[ts.TunnelName] = ts.TxBytes
				}
				if status.TunnelName != "" {
					rx[status.TunnelName] = status.RxBytes
					tx[status.TunnelName] = status.TxBytes
				}
				b.onReconcileHistory(status.ActiveTunnels, rx, tx, "")
			}
		}
	case ipc.EventReconnect:
		var dto ipc.ReconnectStateDTO
		if err := json.Unmarshal(params, &dto); err != nil {
			slog.Debug("event bridge: unmarshal reconnect failed", "error", err)
		} else {
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
		if err := json.Unmarshal(params, &entry); err != nil {
			slog.Debug("event bridge: unmarshal log entry failed", "error", err)
		} else {
			b.app.Event.Emit("log", entry)
		}
	case ipc.EventWifiSSID:
		// SSID change from the helper's wifi monitor. Frontend evaluates
		// Settings.WifiRules and decides whether to (dis)connect a tunnel.
		var payload ipc.WifiSSIDPayload
		if err := json.Unmarshal(params, &payload); err != nil {
			slog.Debug("event bridge: unmarshal wifi_ssid failed", "error", err)
		} else {
			b.app.Event.Emit("wifi_ssid", payload)
		}
	case ipc.EventAutoConnect:
		// Helper auto-connected a tunnel via Wi-Fi rules. Frontend must run
		// the same post-connect refresh (refreshTunnels + refreshStatus) as
		// after a manual connect click so the UI and tray update correctly.
		var payload ipc.AutoConnectPayload
		if err := json.Unmarshal(params, &payload); err != nil {
			slog.Debug("event bridge: unmarshal auto_connect failed", "error", err)
		} else {
			b.app.Event.Emit("auto_connected", payload)
		}
	case ipc.EventCriticalError:
		// A helper background goroutine has died permanently. Surface to
		// the frontend so the user knows tunnel state may stop updating
		// (eventLoop) or wifi rules may stop firing (ssidStartupRule, etc.).
		var payload ipc.CriticalErrorPayload
		if err := json.Unmarshal(params, &payload); err != nil {
			slog.Warn("event bridge: unmarshal critical_error failed", "error", err)
		} else {
			slog.Error("helper background goroutine died permanently", "where", payload.Where, "detail", payload.Detail)
			b.app.Event.Emit("critical_error", payload)
		}
	}
}
