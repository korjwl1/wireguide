package helper

import (
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/korjwl1/wireguide/internal/network"
)

// startShutdownTimer begins (or re-begins) the grace-window countdown. Called
// when the GUI's control connection drops.
//
// CRITICAL DESIGN: wg-quick never shuts down while a tunnel is active. Our
// helper must follow the same principle. If a tunnel is connected, we do NOT
// start the shutdown timer — the helper stays alive indefinitely, just like
// wg-quick's monitor_daemon. The timer only applies when there is no active
// tunnel (i.e., the user disconnected and then closed the GUI).
func (h *Helper) startShutdownTimer() {
	h.armShutdownTimer(shutdownGrace, "GUI disconnected")
}

// markGUISeen records the first GUI attachment and releases anything waiting
// on it (the startup rule re-evaluation).
func (h *Helper) markGUISeen() {
	h.guiSeen.Store(true)
	h.guiSeenOnce.Do(func() {
		if h.guiSeenCh != nil {
			close(h.guiSeenCh)
		}
	})
}

// armStartupGrace arms the no-GUI-yet window Run starts with: the short
// activatedStartupGrace for a launchd-started helper, startupGrace otherwise.
func (h *Helper) armStartupGrace() {
	h.armShutdownTimer(startupGraceFor(h.activated), "startup, no GUI connected yet")
}

// armShutdownTimer preserves active and pending desired tunnels while idle.
func (h *Helper) armShutdownTimer(grace time.Duration, reason string) {
	active := ""
	if h.manager != nil {
		active = h.manager.ActiveTunnel()
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	select {
	case <-h.done:
		return
	default:
	}
	h.armedGrace = grace

	// A tunnel waiting on a restore retry is still wanted (issue #44): exit
	// now and nothing retries it until the GUI next starts the helper.
	if active == "" && (len(h.pendingDesired) > 0 || len(h.activeCfgs) > 0) {
		active = "(pending restore)"
	}
	if active != "" {
		slog.Info("tunnel is active — helper stays alive (wg-quick semantics)",
			"reason", reason, "active_tunnel", active)
		// A previously armed window (e.g. the startup grace) is obsolete
		// now that a tunnel is up — stop it rather than leaving it to fire
		// into a transient not-connected instant later.
		if h.shutdownTimer != nil {
			h.shutdownTimer.Stop()
			h.shutdownTimer = nil
		}
		return
	}

	slog.Info("no active tunnel — starting shutdown grace window",
		"reason", reason, "grace", grace)
	if h.shutdownTimer != nil {
		h.shutdownTimer.Stop()
	}
	var t *time.Timer
	t = time.AfterFunc(grace, func() {
		// Timer.Stop() cannot cancel a callback that has already started,
		// so re-check under the lock that we are still the current timer —
		// otherwise a cancel racing with the fire still shuts the helper
		// down right after a GUI attached.
		// Double-check at fire time: a tunnel may have been activated between
		// timer start and fire (e.g., reconnect monitor brought it back up).
		activeNow := ""
		if h.manager != nil {
			activeNow = h.manager.ActiveTunnel()
		}
		h.mu.Lock()
		if h.shutdownTimer != t {
			h.mu.Unlock()
			return
		}
		pending := len(h.pendingDesired) + len(h.activeCfgs)
		if pending > 0 || activeNow != "" || h.restoreInProgress {
			// Keep a future idle check when a connect temporarily owns the
			// timer. A later failure/withdrawal must not strand the helper.
			t.Reset(grace)
			h.mu.Unlock()
			return
		}
		h.mu.Unlock()
		slog.Info("no reconnect within grace window, shutting down")
		h.shutdown()
	})
	h.shutdownTimer = t
}

// maybeArmShutdownAfterTeardown re-arms the grace window after a tunnel
// teardown that may have dropped the active count to zero. Transient CLI
// clients (`ctl disconnect`, wifi-rule evaluation) never fire the server's
// OnDisconnect, so without this a helper whose GUI already quit — kept alive
// only by its active tunnel — would lose that tunnel and then live forever:
// no GUI, no tunnel, no timer. armShutdownTimer's own active-tunnel guard
// makes this a no-op while any tunnel is still up, and a GUI that IS attached
// keeps its normal lifecycle (its later disconnect arms the window).
func (h *Helper) maybeArmShutdownAfterTeardown(reason string) {
	if h.server == nil || h.server.HasControlConn() {
		return
	}
	h.armShutdownTimer(shutdownGrace, reason)
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

// shutdown initiates a clean exit of the helper process. It does NOT call
// cleanup() directly — instead, it closes the IPC server which causes
// h.server.Serve() (blocked in Run()) to return. Run() then invokes
// h.cleanup() on the deferred path, which DisconnectAll-s tunnels and tears
// down the firewall, and Run() returns to main() which exits the process.
//
// Exit code 0 matters here: the LaunchDaemon plist's KeepAlive is configured
// with SuccessfulExit=false, so launchd respawns only on crash. A successful
// exit driven by this function will NOT restart the daemon — which is what
// the user expects when they click "Quit" in the tray.
func (h *Helper) shutdown() {
	h.server.Shutdown()
}

func (h *Helper) cleanup() {
	h.cleanupOnce.Do(func() {
		slog.Info("helper cleanup starting",
			"connected", h.manager.IsConnected(),
			"call_stack", string(debug.Stack()))
		if h.done != nil {
			close(h.done)
		}
		h.mu.Lock()
		blocked := make([]string, 0, len(h.watchdogBlocked))
		for name := range h.watchdogBlocked {
			blocked = append(blocked, name)
		}
		h.mu.Unlock()
		// Clean shutdown withdraws all wanted tunnels, but preserves
		// watchdog blocks so automation cannot resurrect a suspected loop
		// when the helper starts again. persistDesiredState checks h.done
		// under desiredMu, so no later write can restore wanted tunnels.
		h.desiredMu.Lock()
		if err := saveDesiredIntent(h.dataDir, desiredStateJSON{WatchdogBlocked: blocked}); err != nil {
			slog.Warn("desired-state: preserve watchdog blocks during shutdown failed", "error", err)
		}
		h.desiredMu.Unlock()
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
		h.stopSettleTimer()
		network.UnsubscribeNetworkChange("automation")
		if h.monitor != nil {
			h.monitor.Stop()
		}
		h.connectMu.Lock()
		defer h.connectMu.Unlock()
		// Tear down tunnels BEFORE removing kill-switch / pf rules.
		// Doing it the other way around — flushing pf first — leaves
		// a small but real window where the user's traffic flows
		// over the underlying network unprotected while utun*
		// devices are being closed (DisconnectAll can take seconds
		// per tunnel as wireguard-go drains).
		h.manager.DisconnectAll()
		if err := h.firewall.Cleanup(); err != nil {
			slog.Warn("helper firewall cleanup incomplete", "error", err)
		}
		slog.Info("helper shutdown complete")
	})
}
