package helper

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/korjwl1/wireguide/internal/atomicfile"
	"github.com/korjwl1/wireguide/internal/domain"
)

// Desired tunnel state — the set of tunnels that SHOULD be active, persisted
// across helper restarts so a helper crash doesn't silently drop the user's
// VPN (issue #44).
//
// Background: the tunnel (utun/wintun) lives inside the helper process, so a
// helper crash kills every tunnel with it. After launchd (macOS) or the GUI's
// recovery (Windows/Linux) restarts the helper, every reconnect source was in-memory:
// activeCfgs started empty, the crash journal in internal/tunnel/recovery.go
// only restores system state (DNS, firewall, routes), and the reconnect
// monitor's wake/network triggers skip when the manager reports nothing
// active. The user's only recourse was a manual reconnect — reported live as
// "every time the Mac woke from sleep, WireGuide was disconnected".
//
// This file closes that gap with a small intent file,
// <dataDir>/desired-tunnels.json:
//
//   - The wanted-tunnel list is written on successful Connect
//     (doConnectHeld), Disconnect, and tunnel rename. Clean shutdown clears
//     that list (cleanup). A watchdog trip also writes a durable automation
//     block that survives clean shutdown until a manual Connect succeeds.
//     The monitor's internal teardown-before-reconnect
//     deliberately does NOT touch it — a tunnel mid-reconnect is still
//     wanted. A failed Connect needs no write: activeCfgs rolls back to the
//     pre-call state, which is what the file already records.
//   - Restored once at helper startup: if the file is non-empty and was
//     written during the CURRENT boot, each listed tunnel is reloaded from
//     the user's tunnel store and reconnected. A file older than the current
//     boot means the tunnels died with a previous power cycle — after a
//     reboot the user's expectation is "off", so the file is cleared.
//   - Firewall intent rides along: the file also records whether the kill
//     switch and DNS protection were on. Both live only in the helper's
//     memory (the GUI re-sends them after its own connects), so without
//     this a restored tunnel would come back unprotected. Restore puts the
//     kill switch back BEFORE reconnecting, so a restore that fails keeps
//     the blockade the user had instead of leaking; DNS protection is
//     rebuilt for each tunnel as it reconnects.
//   - Automation rules win: restore runs under reevalMu and skips a tunnel
//     whose rule says "off" on the current network, and a rule-driven
//     disconnect withdraws a pending entry.
//   - Restore failures (e.g. no network yet right after a crash-restart)
//     are kept in pendingDesired, so every later write still lists them and
//     the existing wake/network-change triggers retry them; reconnectFn
//     connects them through the full connect path. Retries come from that
//     set only, never from file entries a concurrent Disconnect just
//     dropped. A Disconnect of the same
//     tunnel withdraws the pending entry.
//
// Semantics by exit path:
//
//	helper crash / kill -9 mid-session   → restore (macOS: launchd restart;
//	                                       Windows/Linux: GUI respawn with
//	                                       --restore-desired)
//	crash while the machine is asleep    → restore on launchd restart / wake
//	upgrade ForceShutdown (no teardown)  → macOS: restore; Windows/Linux: the
//	                                       relaunched GUI is a fresh start, so no
//	clean Quit / `wireguide ctl stop`    → no restore (cleanup cleared the file)
//	reboot / power loss                  → no restore (file predates current boot)
//	Windows logoff / Fast Startup        → no restore (fresh GUI start; boot
//	                                       time alone can't tell)

const desiredStateFile = "desired-tunnels.json"

// bootTimeSlack absorbs clock-source skew between a file's mtime (wall
// clock) and the platform boot time (kern.boottime / /proc/uptime /
// GetTickCount64 — wall-clock derived but sampled and rounded differently).
// Two seconds is far below any real power cycle while comfortably above
// sampling noise.
const bootTimeSlack = 2 * time.Second

type desiredStateJSON struct {
	Tunnels         []string `json:"tunnels"`
	Automatic       []string `json:"automatic_tunnels,omitempty"`
	WatchdogBlocked []string `json:"watchdog_blocked,omitempty"`
	KillSwitch      bool     `json:"kill_switch,omitempty"`
	DNSProtection   bool     `json:"dns_protection,omitempty"`
	DNSAutoOff      bool     `json:"dns_auto_off,omitempty"`
}

func desiredStatePath(dataDir string) string {
	return filepath.Join(dataDir, desiredStateFile)
}

// loadDesiredState returns the persisted tunnel names, or nil when absent.
func loadDesiredState(dataDir string) []string {
	return loadDesiredIntent(dataDir).Tunnels
}

// loadDesiredIntent returns the whole persisted intent. A missing file is the
// common case (nothing wanted), not an error; neither is a corrupt file —
// both mean "nothing to restore".
func loadDesiredIntent(dataDir string) desiredStateJSON {
	if dataDir == "" {
		return desiredStateJSON{}
	}
	data, err := os.ReadFile(desiredStatePath(dataDir))
	if err != nil {
		return desiredStateJSON{}
	}
	var st desiredStateJSON
	if err := json.Unmarshal(data, &st); err != nil {
		return desiredStateJSON{}
	}
	return st
}

func loadWatchdogBlocked(dataDir string) map[string]struct{} {
	blocked := make(map[string]struct{})
	for _, name := range loadDesiredIntent(dataDir).WatchdogBlocked {
		if name != "" {
			blocked[name] = struct{}{}
		}
	}
	return blocked
}

// saveDesiredState writes names with no firewall intent.
func saveDesiredState(dataDir string, names []string) error {
	return saveDesiredIntent(dataDir, desiredStateJSON{Tunnels: names})
}

// saveDesiredIntent writes sorted, de-duplicated names plus the firewall
// intent and watchdog blocks atomically (temp file + rename). With neither
// wanted tunnels nor watchdog blocks, the file is removed.
func saveDesiredIntent(dataDir string, st desiredStateJSON) error {
	if dataDir == "" {
		return nil
	}
	st.Tunnels = normalizeTunnelNames(st.Tunnels)
	wanted := make(map[string]bool, len(st.Tunnels))
	for _, name := range st.Tunnels {
		wanted[name] = true
	}
	automatic := st.Automatic[:0]
	for _, name := range normalizeTunnelNames(st.Automatic) {
		if wanted[name] {
			automatic = append(automatic, name)
		}
	}
	st.Automatic = automatic
	st.WatchdogBlocked = normalizeTunnelNames(st.WatchdogBlocked)
	if len(st.Tunnels) == 0 && len(st.WatchdogBlocked) == 0 {
		clearDesiredState(dataDir)
		return nil
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(desiredStatePath(dataDir))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return atomicfile.WriteFile(desiredStatePath(dataDir), append(data, '\n'), 0600)
}

// clearDesiredState removes the file (best-effort, errors logged).
func clearDesiredState(dataDir string) {
	if dataDir == "" {
		return
	}
	if err := os.Remove(desiredStatePath(dataDir)); err != nil && !os.IsNotExist(err) {
		slog.Warn("desired-state: remove failed", "error", err)
	}
}

func normalizeTunnelNames(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n == "" {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// desiredStatePredatesBoot reports whether the file's last write happened
// before the current boot — i.e. the tunnels it lists died with a previous
// power cycle and must not be resurrected after a reboot.
func desiredStatePredatesBoot(modTime, bootTime time.Time) bool {
	return modTime.Add(bootTimeSlack).Before(bootTime)
}

// persistDesiredState snapshots activeCfgs plus pendingDesired into the
// desired-state file. Called on user-intent transitions (connect success,
// disconnect, rename) and watchdog trips. A watchdog block remains in the
// file even when no tunnel is wanted, so automation cannot recreate a loop
// after the helper restarts.
func (h *Helper) persistDesiredState() {
	if h.dataDir == "" {
		return
	}
	h.desiredMu.Lock()
	defer h.desiredMu.Unlock()
	var st desiredStateJSON
	if h.firewall != nil {
		st.KillSwitch = h.firewall.IsKillSwitchEnabled()
	}
	h.mu.Lock()
	// The setting, not whether rules are installed right now: with no
	// tunnel up, or mid-reconnect, there may be none (issue #48).
	st.DNSProtection = h.dnsProtectionWanted
	st.DNSAutoOff = h.dnsAutoOff
	for name := range h.activeCfgs {
		st.Tunnels = append(st.Tunnels, name)
	}
	for name := range h.pendingDesired {
		st.Tunnels = append(st.Tunnels, name)
	}
	for name := range h.watchdogBlocked {
		st.WatchdogBlocked = append(st.WatchdogBlocked, name)
	}
	// Record the requested setting during suspension and after failed OS
	// applies. An explicit Off must also survive a failed disable (issue #44).
	if h.ksIntentKnown {
		st.KillSwitch = h.killSwitchWanted
	} else {
		st.KillSwitch = st.KillSwitch || h.killSwitchWanted
	}
	h.mu.Unlock()
	h.wifiMu.Lock()
	for _, name := range st.Tunnels {
		if _, automatic := h.autoConnectedBy[name]; automatic {
			st.Automatic = append(st.Automatic, name)
		}
	}
	h.wifiMu.Unlock()
	select {
	case <-h.done:
		// Shutdown began: cleanup() owns the file now (it clears it).
		return
	default:
	}
	if err := saveDesiredIntent(h.dataDir, st); err != nil {
		slog.Warn("desired-state: save failed", "error", err)
	}
}

// desiredActiveFn is handed to the reconnect monitor. When the manager
// reports nothing active but the desired-state file lists tunnels, wake and
// network-change triggers must still fire (issue #44: the old guard skipped
// them, so a crash-restarted helper whose restore attempt failed never
// retried and the user had to reconnect by hand).
func (h *Helper) desiredActiveFn() bool {
	return len(loadDesiredState(h.dataDir)) > 0
}

// tunnelActive reports whether the manager currently has name connected.

func (h *Helper) tunnelActive(name string) bool {
	for _, st := range tunnelStatuses(h) {
		if st != nil && st.TunnelName == name && st.State == domain.StateConnected {
			return true
		}
	}
	return false
}

// wantedTunnelNames exposes intent during transport teardown/backoff and
// pending crash restore without misreporting disconnected tunnels as active.
func (h *Helper) wantedTunnelNames() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	names := make(map[string]bool)
	for n := range h.activeCfgs {
		if _, blocked := h.watchdogBlocked[n]; !blocked {
			names[n] = true
		}
	}
	for n := range h.pendingDesired {
		if _, blocked := h.watchdogBlocked[n]; !blocked {
			names[n] = true
		}
	}
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
