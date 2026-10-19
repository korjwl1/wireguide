package helper

import (
	"log/slog"
	"os"
	"time"
)

// restoreDesiredTunnels runs once at helper startup (via goSafe). It is the
// issue #44 fix: re-establish tunnels that were active when the previous
// helper instance died without a clean shutdown.
//
// The whole loop holds connectMu: a GUI Connect/Disconnect issued during the
// restore must not interleave with the per-tunnel connects or the final
// desired-state rewrite. The helper only just started, so the blocking
// window is a fresh session's first seconds.
func (h *Helper) restoreDesiredTunnels() {
	h.mu.Lock()
	h.restoreInProgress = true
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		h.restoreInProgress = false
		grace := h.armedGrace
		h.mu.Unlock()
		if h.server != nil && !h.server.HasControlConn() {
			if grace == 0 {
				grace = startupGraceFor(h.activated)
			}
			h.armShutdownTimer(grace, "startup restore completed, no GUI attached")
		}
	}()
	intent := loadDesiredIntent(h.dataDir)
	names := make([]string, 0, len(intent.Tunnels))
	for _, name := range intent.Tunnels {
		if !h.isWatchdogBlocked(name) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		if len(intent.Tunnels) > 0 {
			// The helper died after recording a watchdog trip but before
			// finishing teardown. Remove the now-blocked desired entry.
			h.connectMu.Lock()
			h.persistDesiredState()
			h.connectMu.Unlock()
		}
		return
	}

	if !h.restoreOnStart {
		slog.Info("desired-state: fresh helper start (not a crash respawn); clearing",
			"tunnels", names)
		// Rewrite from what is actually up rather than delete: a GUI
		// Connect may already have landed and written its own entry.
		h.connectMu.Lock()
		h.persistDesiredState()
		h.connectMu.Unlock()
		return
	}

	if boot, err := systemBootTimeNow(); err == nil {
		if info, ierr := os.Stat(desiredStatePath(h.dataDir)); ierr == nil &&
			desiredStatePredatesBoot(info.ModTime(), boot) {
			slog.Info("desired-state predates current boot; clearing (tunnels died with a previous power cycle)",
				"tunnels", names,
				"file_mtime", info.ModTime().Format(time.RFC3339),
				"boot", boot.Format(time.RFC3339))
			h.mu.Lock()
			blocked := make([]string, 0, len(h.watchdogBlocked))
			for name := range h.watchdogBlocked {
				blocked = append(blocked, name)
			}
			h.mu.Unlock()
			if err := saveDesiredIntent(h.dataDir, desiredStateJSON{WatchdogBlocked: blocked}); err != nil {
				slog.Warn("desired-state: clearing pre-boot tunnels failed", "error", err)
			}
			return
		}
	} else {
		// Boot time unavailable (unusual platform / syscall failure):
		// restore without the reboot check. The crash-during-sleep case this
		// fixes is same-boot by definition, and an unwanted restore after a
		// reboot is recoverable with one disconnect.
		slog.Warn("desired-state: boot time unavailable, skipping reboot check", "error", err)
	}

	h.connectMu.Lock()
	h.registerPendingRestore()
	h.connectMu.Unlock()
	if h.userTunnelStore == nil {
		slog.Warn("desired-state: no tunnel store available; leaving file for later triggers",
			"tunnels", names)
		return
	}

	restored, failed, missing, ruledOff := 0, 0, 0, 0

	// Same lock order as automation (reevalMu → connectMu): no rule pass
	// can interleave with the restore, and one that ran before it already
	// saw these tunnels down, so restore checks the rules itself below.
	h.reevalMu.Lock()
	defer h.reevalMu.Unlock()
	// Rule verdicts are read before connectMu: the network context shells
	// out (gateway MAC, interface IPs), and a GUI Connect/Disconnect must
	// not wait on that.
	ruleOff := make(map[string]bool, len(names))
	for _, name := range names {
		ruleOff[name] = restoreRuleSaysOff(h, name)
	}
	h.connectMu.Lock()
	defer h.connectMu.Unlock()

	// The user settings and any live update are authoritative. The crash
	// journal is only a fallback when neither is available.
	h.mu.Lock()
	if !h.dnsIntentKnown && intent.DNSProtection {
		h.dnsProtectionWanted = true
	}
	if !h.dnsIntentExplicit {
		h.dnsAutoOff = intent.DNSAutoOff
	}

	// Kill switch first: the user had the blockade up, and the crash
	// recovery above removed it. doConnectHeld handles connecting under it.
	if (intent.KillSwitch || h.ksRestoreOn) && !h.ksIntentKnown {
		h.killSwitchWanted = true
		h.ksIntentKnown = true
	}
	restoreKillSwitch := h.killSwitchWanted
	h.mu.Unlock()
	if restoreKillSwitch {
		if err := h.reconcileKillSwitch(true, time.Now()); err != nil {
			slog.Error("desired-state: restore kill switch failed", "error", err)
		}
	}

	for _, name := range names {
		// Bounded shutdown: cleanup() closes h.done before DisconnectAll;
		// stop restoring so we don't fight the teardown.
		select {
		case <-h.done:
			return
		default:
		}
		// A GUI or automation connect may have raced us onto this tunnel
		// while earlier restores were in flight — don't double-connect.
		if h.tunnelActive(name) {
			restored++
			continue
		}
		h.mu.Lock()
		_, stillPending := h.pendingDesired[name]
		h.mu.Unlock()
		if !stillPending || h.isWatchdogBlocked(name) {
			h.dropPendingRestore(name)
			continue
		}
		cfg, err := h.userTunnelStore.Load(name)
		if err != nil {
			h.dropPendingRestore(name)
			missing++
			slog.Warn("desired-state: tunnel config missing, dropping",
				"tunnel", name, "error", err)
			continue
		}
		if ruleOff[name] {
			h.dropPendingRestore(name)
			ruledOff++
			slog.Info("desired-state: automation rule says off on this network, not restoring",
				"tunnel", name)
			continue
		}
		if h.automaticLANConflict(cfg) {
			h.mu.Lock()
			if h.pendingDesired == nil {
				h.pendingDesired = make(map[string]struct{})
			}
			h.pendingDesired[name] = struct{}{}
			h.mu.Unlock()
			continue
		}
		if err := restoreConnect(h, cfg); err != nil {
			failed++
			slog.Warn("desired-state: restore connect failed; keeping entry for reconnect triggers",
				"tunnel", name, "error", err)
			h.mu.Lock()
			if h.pendingDesired == nil {
				h.pendingDesired = make(map[string]struct{})
			}
			h.pendingDesired[name] = struct{}{}
			h.mu.Unlock()
			continue
		}
		restored++
	}

	// Rewrite the file from what should STILL be wanted: active tunnels
	// plus pending (failed) ones, minus tunnels whose configs no longer
	// exist. Needed even when nothing connected, to drop missing configs.
	// Skipped when shutdown began mid-restore — cleanup's
	// clearDesiredState then has the last word.
	select {
	case <-h.done:
		return
	default:
	}
	h.persistDesiredState()
	slog.Info("desired-state restore complete",
		"restored", restored, "failed", failed, "missing_configs", missing,
		"ruled_off", ruledOff, "total", len(names))
}
