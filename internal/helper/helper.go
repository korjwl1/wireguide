// Package helper implements the privileged helper process.
// Runs as root/admin, accepts RPC calls from the GUI, manages tunnel + firewall.
//
// The package is split across three files:
//   - helper.go   (this file) — Helper struct + Run() lifecycle
//   - handlers.go — RPC method handlers
//   - events.go   — status diff + broadcast loop, status conversion
package helper

import (
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/reconnect"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// goSafe runs fn in a goroutine with panic recovery. Without this, a panic
// in ANY helper goroutine crashes the whole process — which is exactly what
// we've been unable to diagnose because the helper dies silently with no log
// trail. Every background goroutine in the helper should be started via this
// wrapper so panics are captured, logged, and surfaced instead of vanishing.
func goSafe(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("goroutine panic",
					"where", name,
					"panic", fmt.Sprintf("%v", r),
					"stack", string(debug.Stack()))
			}
		}()
		fn()
	}()
}

// shutdownGrace is the window the helper waits after a GUI disconnect before
// terminating itself. Short enough to prevent orphan processes, long enough to
// tolerate a normal GUI restart.
const shutdownGrace = 10 * time.Second

// Helper holds the helper process state.
type Helper struct {
	server   *ipc.Server
	manager  *tunnel.Manager
	firewall firewall.FirewallManager
	monitor  *reconnect.Monitor

	// logLevel is the runtime-mutable slog level. Helper.SetLogLevel (and
	// the Settings UI) writes to this; the broadcast handler reads it for
	// every record. Info by default.
	logLevel *slog.LevelVar

	mu              sync.Mutex
	activeCfg       *domain.WireGuardConfig // cached for reconnect
	scriptsAllowed  bool
	scriptAllowlist *ScriptAllowlist // persistent allowlist for script approval

	// shutdownTimer is a singleton grace-window timer. When the control
	// connection drops we Reset it; when the GUI reconnects we Stop it. This
	// avoids the previous bug where every disconnect spawned a fresh goroutine
	// and multiple shutdowns could race.
	shutdownTimer *time.Timer

	done        chan struct{}
	cleanupOnce sync.Once
}

// Run starts the helper listening on addr. Blocks until shutdown.
// ownerUID: UID to chown socket to (Unix only, use -1 on Windows).
// dataDir: persistent data dir for crash recovery state.
func Run(addr string, ownerUID int, dataDir string) error {
	listener, err := ipc.Listen(addr, ownerUID)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	manager := tunnel.NewManager(dataDir)
	fw := firewall.NewPlatformFirewall()

	h := &Helper{
		server:          ipc.NewServer(listener, ownerUID),
		manager:         manager,
		firewall:        fw,
		logLevel:        new(slog.LevelVar), // defaults to Info
		scriptAllowlist: NewScriptAllowlist(dataDir),
		done:            make(chan struct{}),
	}

	// Install the broadcast slog handler BEFORE the first log call so
	// everything that follows (crash recovery notices, manager init,
	// handler registration) gets piped to subscribed GUIs.
	slog.SetDefault(slog.New(newBroadcastHandler(h.logLevel, func() func(string, interface{}) {
		if h.server == nil {
			return nil
		}
		return h.server.Broadcast
	})))

	// Crash recovery (now logs via broadcast handler)
	if recovered := tunnel.RecoverFromCrash(dataDir); recovered != "" {
		slog.Warn("recovered from previous crash", "tunnel", recovered)
	}

	// Reconnect monitor — uses cached config
	h.monitor = reconnect.NewMonitor(manager, h.reconnectFn, h.onReconnectState, reconnect.DefaultConfig())
	h.monitor.Start()

	// Register RPC handlers
	h.registerHandlers()

	// Grace-window shutdown on GUI disconnect.
	h.server.OnConnect(h.cancelShutdownTimer)
	h.server.OnDisconnect(h.startShutdownTimer)

	// Start event emitter (diff loop)
	goSafe("eventLoop", h.eventLoop)

	// Top-level panic recovery for the Serve loop itself. If Accept or any
	// per-conn handler panics unrecovered, we at least want a stack trace.
	defer func() {
		if r := recover(); r != nil {
			slog.Error("helper Run panic",
				"panic", fmt.Sprintf("%v", r),
				"stack", string(debug.Stack()))
		}
	}()

	slog.Info("helper listening", "addr", addr, "pid", "daemon")

	// Serve (blocks until shutdown)
	err = h.server.Serve()
	h.cleanup()
	return err
}

// reconnectFn is the callback passed to reconnect.Monitor. It fetches the
// currently cached active config under lock and asks the tunnel manager to
// reconnect. Returns an error if no config is cached (meaning the user has
// manually disconnected, in which case reconnection is not desired).
func (h *Helper) reconnectFn() error {
	h.mu.Lock()
	cfg := h.activeCfg
	allowed := h.scriptsAllowed
	h.mu.Unlock()
	if cfg == nil {
		return fmt.Errorf("no cached config for reconnect")
	}
	return h.manager.Connect(cfg, allowed)
}

// onReconnectState forwards reconnection state changes to any subscribed GUI.
func (h *Helper) onReconnectState(state reconnect.State) {
	h.server.Broadcast(ipc.EventReconnect, ipc.ReconnectStateDTO{
		Reconnecting: state.Reconnecting,
		Attempt:      state.Attempt,
		MaxAttempts:  state.MaxAttempts,
		NextRetry:    state.NextRetry,
	})
}

// startShutdownTimer begins (or re-begins) the grace-window countdown. Called
// when the GUI's control connection drops.
//
// CRITICAL DESIGN: wg-quick never shuts down while a tunnel is active. Our
// helper must follow the same principle. If a tunnel is connected, we do NOT
// start the shutdown timer — the helper stays alive indefinitely, just like
// wg-quick's monitor_daemon. The timer only applies when there is no active
// tunnel (i.e., the user disconnected and then closed the GUI).
func (h *Helper) startShutdownTimer() {
	active := ""
	if h.manager != nil {
		active = h.manager.ActiveTunnel()
	}

	if active != "" {
		slog.Info("GUI disconnected but tunnel is active — helper stays alive (wg-quick semantics)",
			"active_tunnel", active)
		return
	}

	slog.Info("GUI disconnected, no active tunnel — starting shutdown grace window",
		"grace", shutdownGrace)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.shutdownTimer != nil {
		h.shutdownTimer.Stop()
	}
	h.shutdownTimer = time.AfterFunc(shutdownGrace, func() {
		// Double-check at fire time: a tunnel may have been activated between
		// timer start and fire (e.g., reconnect monitor brought it back up).
		if t := h.manager.ActiveTunnel(); t != "" {
			slog.Info("shutdown timer fired but tunnel is now active — aborting shutdown",
				"active_tunnel", t)
			return
		}
		slog.Info("no reconnect within grace window, shutting down")
		h.shutdown()
	})
}

// cancelShutdownTimer aborts a pending grace-window shutdown. Called when the
// GUI reconnects before the timer fires.
func (h *Helper) cancelShutdownTimer() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.shutdownTimer != nil {
		if h.shutdownTimer.Stop() {
			slog.Info("GUI reconnected within grace window, shutdown cancelled")
		}
		h.shutdownTimer = nil
	}
}

func (h *Helper) shutdown() {
	h.server.Shutdown()
}

func (h *Helper) cleanup() {
	h.cleanupOnce.Do(func() {
		slog.Info("helper cleanup starting",
			"connected", h.manager.IsConnected(),
			"call_stack", string(debug.Stack()))
		close(h.done)
		h.mu.Lock()
		t := h.shutdownTimer
		h.shutdownTimer = nil
		h.mu.Unlock()
		if t != nil {
			t.Stop()
		}
		h.monitor.Stop()
		h.firewall.Cleanup()
		if h.manager.IsConnected() {
			_ = h.manager.Disconnect()
		}
		slog.Info("helper shutdown complete")
	})
}
