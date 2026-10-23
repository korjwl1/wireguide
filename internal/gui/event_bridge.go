package gui

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

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
	// onQuitRequested terminates the app. Fired for ipc.EventQuit, which
	// the helper broadcasts when someone runs `wireguide ctl stop`.
	onQuitRequested func()

	mu           sync.Mutex
	subscribedTo *ipc.Client // tracks which client we're currently subscribed on
}

func newEventBridge(
	app *application.App,
	clients *ipc.ClientHolder,
	onStatusChange func(activeNames []string, handshakeMap map[string]bool),
	onReconcileHistory func(activeNames []string, rx, tx map[string]int64, reason string),
	onQuitRequested func(),
) *eventBridge {
	return &eventBridge{
		app:                app,
		clients:            clients,
		onStatusChange:     onStatusChange,
		onReconcileHistory: onReconcileHistory,
		onQuitRequested:    onQuitRequested,
	}
}

// start attaches the event subscription to the current client.
func (b *eventBridge) start() {
	b.resubscribe()
}

// Resubscribe repairs a missing event stream without replacing the control
// connection or interrupting a long-running VPN operation.
func (b *eventBridge) Resubscribe() {
	b.mu.Lock()
	previous := b.subscribedTo
	b.mu.Unlock()
	if b.resubscribe() {
		if previous != nil && previous != b.clients.Get() {
			b.app.Event.Emit("helper_reset", struct{}{})
		} else {
			b.app.Event.Emit("tunnels_changed", struct{}{})
		}
	}
}

func (b *eventBridge) resubscribe() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.clients.Get()
	if c == nil || c.IsClosed() || (b.subscribedTo == c && c.HasSubscription()) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.SubscribeContext(ctx, func(method string, params json.RawMessage) {
		// Order callbacks against resubscription; ignore replaced clients.
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.subscribedTo == c && b.clients.Get() == c {
			b.handleEvent(method, params)
		}
	}); err != nil {
		slog.Warn("event subscription failed", "error", err)
		return false
	}
	b.subscribedTo = c
	return true
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
				names, handshakes := connectedStatusIndicators(status)
				b.onStatusChange(names, handshakes)
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
		// The helper owns automation decisions; the frontend displays the
		// observed SSID and permission state.
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
	case ipc.EventAutomationSkipped:
		var payload ipc.AutomationSkippedPayload
		if err := json.Unmarshal(params, &payload); err != nil {
			slog.Debug("event bridge: unmarshal automation_skipped failed", "error", err)
		} else {
			b.app.Event.Emit("automation_skipped", payload)
		}
	case ipc.EventForcedDisconnect:
		// The helper tore a tunnel down on its own (loop watchdog, issue
		// #49). EventStatus already shows it as down; the frontend tells
		// the user why, since it won't reconnect by itself.
		var payload ipc.ForcedDisconnectPayload
		if err := json.Unmarshal(params, &payload); err != nil {
			slog.Debug("event bridge: unmarshal forced_disconnect failed", "error", err)
		} else {
			b.app.Event.Emit("forced_disconnect", payload)
		}
	case ipc.EventQuit:
		// `wireguide ctl stop` — the user asked for the whole app to go
		// away. Run the same teardown the tray's Quit item does.
		//
		// Dispatch teardown so its blocking RPCs do not hold up the
		// event reader. Control responses use a separate connection.
		slog.Info("event bridge: quit requested by CLI")
		if b.onQuitRequested != nil {
			go b.onQuitRequested()
		}
	case ipc.EventSettingsChanged:
		// A setting was applied through another client (the CLI). Forward
		// the changed value so the Settings UI updates its toggle live.
		var payload ipc.SettingsChangedPayload
		if err := json.Unmarshal(params, &payload); err != nil {
			slog.Debug("event bridge: unmarshal settings_changed failed", "error", err)
		} else {
			b.app.Event.Emit("settings_changed", payload)
		}
	case ipc.EventRecoveryWarning:
		var payload ipc.RecoveryWarningPayload
		if err := json.Unmarshal(params, &payload); err != nil {
			slog.Warn("invalid recovery warning", "error", err)
		} else {
			b.app.Event.Emit("recovery_warning", payload)
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

// A missing helper cannot attest to a live connection. Clear indicators without
// inventing a disconnect/history record; restored status will repopulate them.
func (b *eventBridge) clearConnectionIndicators() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.onStatusChange != nil {
		b.onStatusChange(nil, nil)
	}
}
