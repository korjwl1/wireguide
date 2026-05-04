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
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/reconnect"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/tunnel"
	"github.com/korjwl1/wireguide/internal/wifi"
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

	mu         sync.Mutex
	activeCfgs map[string]*domain.WireGuardConfig // cached for reconnect, keyed by tunnel name

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

	// latencyByTunnel caches the most recent endpoint round-trip time
	// (in ms) per tunnel name. Updated by latencyLoop every 30s; read by
	// statusDTO on every broadcast tick. Keyed by tunnel name so
	// multi-tunnel setups show per-tunnel latency.
	latencyMu       sync.Mutex
	latencyByTunnel map[string]float64

	// wifiMon polls CurrentSSID every 5s. The helper itself evaluates
	// the user's wifi rules on every change so auto-connect /
	// auto-disconnect work whether or not a GUI is running. The
	// EventWifiSSID broadcast is still sent so a live GUI can react
	// (e.g. show a toast).
	wifiMon *wifi.Monitor

	// wifiMu guards autoConnectedBy. The map records "this tunnel
	// was last activated by a wifi rule on this SSID" so a later
	// SSID change can tell auto-managed tunnels apart from manually
	// connected ones and only touch the former.
	wifiMu          sync.Mutex
	autoConnectedBy map[string]string

	// userTunnelStore reads .conf files from the user's home dir
	// (derived from the uid passed at launch). Needed so wifi rules
	// can connect tunnels that aren't already in activeCfgs — i.e.
	// the user has never opened them via the GUI in this session.
	userTunnelStore *storage.TunnelStore
	userAppSupport  string

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
		activeCfgs:      make(map[string]*domain.WireGuardConfig),
		latencyByTunnel: make(map[string]float64),
		autoConnectedBy: make(map[string]string),
		logLevel:        new(slog.LevelVar), // defaults to Info
		done:            make(chan struct{}),
	}

	// Derive the user's Application Support dir from the uid the
	// LaunchDaemon plist passed in (`--uid=501` typically). Helper
	// runs as root, so os.UserHomeDir() returns /var/root — useless.
	// On platforms we haven't wired up (linux/windows), this returns
	// empty and the wifi-rules helper-side path stays a no-op.
	if appSupport, err := deriveUserAppSupport(ownerUID); err == nil && appSupport != "" {
		h.userAppSupport = appSupport
		h.userTunnelStore = storage.NewTunnelStore(filepath.Join(appSupport, "tunnels"))
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
	if recovered := tunnel.RecoverFromCrash(dataDir); len(recovered) > 0 {
		slog.Warn("recovered from previous crash", "tunnels", recovered)
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

	// Start endpoint latency probe loop. Runs at a slow tick (~30s) so
	// it doesn't add measurable load; ICMP pings are blocking and the
	// goroutine is supervised by goSafe like every other long-running
	// helper background task.
	goSafe("latencyLoop", h.latencyLoop)

	// Start Wi-Fi SSID monitor. On change we broadcast the event for
	// any GUI listener AND evaluate the user's wifi rules right here
	// so auto-connect / auto-disconnect keep working when the GUI is
	// closed.
	h.wifiMon = wifi.NewMonitor(nil, func(oldSSID, newSSID string) {
		h.server.Broadcast(ipc.EventWifiSSID, ipc.WifiSSIDPayload{
			OldSSID: oldSSID,
			NewSSID: newSSID,
		})
		h.handleSSIDChange(oldSSID, newSSID)
	})
	h.wifiMon.Start()

	// Re-evaluate rules once on startup. The autoConnectedBy map is
	// in-memory only, so a helper crash + LaunchDaemon restart loses
	// the "this tunnel was rule-managed" markers. Without this synthetic
	// re-eval, a tunnel recovered from crash on a SSID with no rule
	// stays up indefinitely until the user manually disconnects.
	// Running it here, after wifiMon starts, also handles the boot
	// case where the helper starts before the Wi-Fi has joined.
	goSafe("ssidStartupRule", func() {
		// Brief delay to let the network stack settle and crash
		// recovery finish — racing handleSSIDChange against an
		// in-flight RecoverFromCrash would corrupt activeCfgs.
		select {
		case <-h.done:
			return
		case <-time.After(3 * time.Second):
		}
		// Re-check shutdown after the sleep — `cleanup()` running
		// concurrently calls h.manager.DisconnectAll(), and we'd
		// otherwise race handleSSIDChange's manager.Connect against
		// a torn-down manager.
		select {
		case <-h.done:
			return
		default:
		}
		ssid := wifi.CurrentSSID()
		if ssid == "" {
			return
		}
		slog.Info("startup rule re-evaluation", "ssid", ssid)
		h.handleSSIDChange("", ssid)
	})

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

// reconnectFn is the callback passed to reconnect.Monitor. When name is
// non-empty, it reconnects only that specific tunnel. When name is empty
// (legacy sleep/wake path), it reconnects all cached tunnels.
// The connectMu is held during Connect to prevent races with concurrent
// GUI connect/disconnect calls.
func (h *Helper) reconnectFn(name string) error {
	h.mu.Lock()
	cfgs := h.copyActiveCfgs()
	h.mu.Unlock()

	if name != "" {
		cfg, ok := cfgs[name]
		if !ok {
			return fmt.Errorf("no cached config for tunnel %q", name)
		}
		h.connectMu.Lock()
		err := h.manager.Connect(cfg)
		h.connectMu.Unlock()
		return err
	}

	// Legacy path: reconnect all tunnels.
	if len(cfgs) == 0 {
		return fmt.Errorf("no cached config for reconnect")
	}
	var lastErr error
	for _, cfg := range cfgs {
		h.connectMu.Lock()
		err := h.manager.Connect(cfg)
		h.connectMu.Unlock()
		if err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// copyActiveCfgs returns a shallow copy of the active configs map.
// Caller MUST hold h.mu.
func (h *Helper) copyActiveCfgs() map[string]*domain.WireGuardConfig {
	cp := make(map[string]*domain.WireGuardConfig, len(h.activeCfgs))
	for k, v := range h.activeCfgs {
		cp[k] = v
	}
	return cp
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
	// DNS servers are stored from any active config's Interface.DNS
	for _, cfg := range h.activeCfgs {
		if len(cfg.Interface.DNS) > 0 {
			h.fwSavedDNSServers = cfg.Interface.DNS
			break
		}
	}
	h.mu.Unlock()

	if !ksEnabled && !dnsEnabled {
		slog.Debug("suspendFirewall: no firewall rules active, nothing to suspend")
		return nil
	}

	slog.Info("suspending firewall rules for reconnect",
		"kill_switch", ksEnabled, "dns_protection", dnsEnabled)

	// Disable DNS protection first (it may be a sub-anchor of the kill switch).
	dnsDisabled := false
	if dnsEnabled {
		if err := h.firewall.DisableDNSProtection(); err != nil {
			slog.Warn("suspendFirewall: failed to disable DNS protection", "error", err)
		} else {
			dnsDisabled = true
		}
	}
	if ksEnabled {
		if err := h.firewall.DisableKillSwitch(); err != nil {
			// We just turned DNS protection off but the kill switch
			// is still on — that's an inconsistent state. Try to
			// re-enable DNS protection so the system goes back to
			// where it was, and surface the error to the caller so
			// resumeFirewall isn't called against a state that
			// already half-resumed.
			if dnsDisabled {
				h.mu.Lock()
				dnsServers := h.fwSavedDNSServers
				h.mu.Unlock()
				ifaceName := ""
				if status := h.manager.Status(); status != nil {
					ifaceName = status.InterfaceName
				}
				if ifaceName != "" && len(dnsServers) > 0 {
					if rollbackErr := h.firewall.EnableDNSProtection(ifaceName, dnsServers); rollbackErr != nil {
						slog.Error("suspendFirewall: DNS protection rollback ALSO failed",
							"error", rollbackErr)
					}
				}
			}
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
	for _, cfg := range h.activeCfgs {
		ifaceAddresses = append(ifaceAddresses, cfg.Interface.Address...)
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
		if h.wifiMon != nil {
			h.wifiMon.Stop()
		}
		h.monitor.Stop()
		// Tear down tunnels BEFORE removing kill-switch / pf rules.
		// Doing it the other way around — flushing pf first — leaves
		// a small but real window where the user's traffic flows
		// over the underlying network unprotected while utun*
		// devices are being closed (DisconnectAll can take seconds
		// per tunnel as wireguard-go drains).
		if h.manager.IsConnected() {
			h.manager.DisconnectAll()
		}
		h.firewall.Cleanup()
		slog.Info("helper shutdown complete")
	})
}
