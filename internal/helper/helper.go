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
	"os"
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
// goSafe runs fn in a goroutine with panic recovery and automatic restart.
// If fn panics, the panic is logged and fn is restarted after a 1-second
// backoff, up to maxRestarts times. This ensures critical background loops
// (like the event broadcast loop) survive transient panics instead of dying
// permanently. If fn returns normally (no panic), it is NOT restarted.
func goSafe(name string, fn func()) {
	const maxRestarts = 5
	go func() {
		for attempt := 0; attempt <= maxRestarts; attempt++ {
			panicked := true
			func() {
				defer func() {
					if r := recover(); r != nil {
						slog.Error("goroutine panic (will restart)",
							"where", name,
							"panic", fmt.Sprintf("%v", r),
							"stack", string(debug.Stack()),
							"attempt", attempt+1,
							"max", maxRestarts+1)
					}
				}()
				fn()
				panicked = false
			}()
			if !panicked {
				return // fn returned normally — done.
			}
			// Backoff before restart to avoid tight panic loops.
			time.Sleep(1 * time.Second)
		}
		slog.Error("goroutine exceeded max restarts, giving up", "where", name)
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

	// connectMu serializes Connect/Disconnect calls. Without this, two
	// concurrent GUI connections could race on activeCfg, with the loser's
	// rollback overwriting the winner's config.
	connectMu sync.Mutex

	// logLevel is the runtime-mutable slog level. Helper.SetLogLevel (and
	// the Settings UI) writes to this; the broadcast handler reads it for
	// every record. Info by default.
	logLevel *slog.LevelVar

	mu        sync.Mutex
	activeCfg *domain.WireGuardConfig // cached for reconnect

	// Firewall state saved during reconnect suspend/resume cycle.
	// These track what was active before suspend so resume can restore it.
	fwSavedKillSwitch    bool
	fwSavedDNSProtection bool
	fwSavedDNSServers    []string // DNS servers to re-enable on resume

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
		logLevel: new(slog.LevelVar), // defaults to Info
		done:     make(chan struct{}),
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
	h.monitor.SetFirewallCallbacks(h.suspendFirewall, h.resumeFirewall)
	h.monitor.Start()

	// Register RPC handlers
	h.registerHandlers()

	// Grace-window shutdown on GUI disconnect — only when NOT running as a
	// LaunchDaemon. When the daemon plist has KeepAlive=true, launchd
	// handles restarts; the helper should stay alive even when no GUI is
	// connected (so the next GUI launch connects instantly without a
	// password prompt). In osascript/dev mode, the helper still shuts down
	// after the grace window to avoid orphan processes.
	if !isDaemon() {
		h.server.OnConnect(h.cancelShutdownTimer)
		h.server.OnDisconnect(h.startShutdownTimer)
	} else {
		slog.Info("running as LaunchDaemon — shutdown grace disabled")
	}

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
	h.mu.Unlock()
	if cfg == nil {
		return fmt.Errorf("no cached config for reconnect")
	}
	return h.manager.Connect(cfg)
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

// isDaemon returns true when the helper was started by launchd (LaunchDaemon).
// launchd always sets the process's parent PID to 1 (init/launchd).
func isDaemon() bool {
	return os.Getppid() == 1
}

// suspendFirewall saves the current firewall state and disables all firewall
// rules. Called by the reconnect monitor before Disconnect so that old pf rules
// referencing the previous utun interface name don't block the new connection.
func (h *Helper) suspendFirewall() error {
	ksEnabled := h.firewall.IsKillSwitchEnabled()
	dnsEnabled := h.firewall.IsDNSProtectionEnabled()

	h.mu.Lock()
	h.fwSavedKillSwitch = ksEnabled
	h.fwSavedDNSProtection = dnsEnabled
	// DNS servers are stored from the active config's Interface.DNS
	if h.activeCfg != nil {
		h.fwSavedDNSServers = h.activeCfg.Interface.DNS
	}
	h.mu.Unlock()

	if !ksEnabled && !dnsEnabled {
		slog.Debug("suspendFirewall: no firewall rules active, nothing to suspend")
		return nil
	}

	slog.Info("suspending firewall rules for reconnect",
		"kill_switch", ksEnabled, "dns_protection", dnsEnabled)

	// Disable DNS protection first (it may be a sub-anchor of the kill switch).
	if dnsEnabled {
		if err := h.firewall.DisableDNSProtection(); err != nil {
			slog.Warn("suspendFirewall: failed to disable DNS protection", "error", err)
		}
	}
	if ksEnabled {
		if err := h.firewall.DisableKillSwitch(); err != nil {
			return fmt.Errorf("suspendFirewall: disable kill switch: %w", err)
		}
	}

	return nil
}

// resumeFirewall re-enables firewall rules that were active before the
// reconnect suspend. It reads the NEW interface name and endpoints from the
// tunnel manager so the pf rules match the newly created utun interface.
func (h *Helper) resumeFirewall() error {
	h.mu.Lock()
	restoreKS := h.fwSavedKillSwitch
	restoreDNS := h.fwSavedDNSProtection
	savedDNSServers := h.fwSavedDNSServers
	var ifaceAddresses []string
	if h.activeCfg != nil {
		ifaceAddresses = h.activeCfg.Interface.Address
	}
	// Clear saved state so a second resume is a no-op.
	h.fwSavedKillSwitch = false
	h.fwSavedDNSProtection = false
	h.fwSavedDNSServers = nil
	h.mu.Unlock()

	if !restoreKS && !restoreDNS {
		slog.Debug("resumeFirewall: no firewall rules to restore")
		return nil
	}

	status := h.manager.Status()
	ifaceName := ""
	if status != nil {
		ifaceName = status.InterfaceName
	}

	slog.Info("resuming firewall rules after reconnect",
		"kill_switch", restoreKS, "dns_protection", restoreDNS,
		"new_interface", ifaceName)

	if restoreKS {
		if ifaceName == "" {
			slog.Warn("resumeFirewall: no interface name available, cannot re-enable kill switch")
		} else {
			endpoints := h.manager.ResolvedEndpoints()
			if len(endpoints) == 0 {
				slog.Warn("resumeFirewall: no resolved endpoints, cannot re-enable kill switch")
			} else {
				if err := h.firewall.EnableKillSwitch(ifaceName, ifaceAddresses, endpoints); err != nil {
					slog.Error("resumeFirewall: failed to re-enable kill switch", "error", err)
					return fmt.Errorf("resumeFirewall: enable kill switch: %w", err)
				}
			}
		}
	}

	if restoreDNS {
		if ifaceName == "" {
			slog.Warn("resumeFirewall: no interface name available, cannot re-enable DNS protection")
		} else if len(savedDNSServers) == 0 {
			slog.Warn("resumeFirewall: no DNS servers saved, cannot re-enable DNS protection")
		} else {
			if err := h.firewall.EnableDNSProtection(ifaceName, savedDNSServers); err != nil {
				slog.Error("resumeFirewall: failed to re-enable DNS protection", "error", err)
				return fmt.Errorf("resumeFirewall: enable DNS protection: %w", err)
			}
		}
	}

	return nil
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
