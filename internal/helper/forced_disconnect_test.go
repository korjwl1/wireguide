package helper

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// A watchdog trip drops the tunnel from the cached configs and the desired
// state, so neither the wake reconnect nor a crash restore brings the
// looping tunnel back (issue #49).
func TestForcedDisconnectDropsTunnelEverywhere(t *testing.T) {
	h := newPendingTestHelper(t, "vpn1", "vpn2")
	h.activeCfgs["vpn1"] = &domain.WireGuardConfig{Name: "vpn1"}
	h.activeCfgs["vpn2"] = &domain.WireGuardConfig{Name: "vpn2"}
	h.persistDesiredState()

	h.handleForcedDisconnect(tunnel.NewForcedDisconnect("vpn1", "utun9", "routing loop detected", nil))

	if _, ok := h.activeCfgs["vpn1"]; ok {
		t.Fatal("vpn1 still cached; the wake reconnect would bring it back")
	}
	if _, ok := h.activeCfgs["vpn2"]; !ok {
		t.Fatal("vpn2 was dropped too")
	}
	if got := loadDesiredState(h.dataDir); len(got) != 1 || got[0] != "vpn2" {
		t.Fatalf("desired state = %v; want [vpn2]", got)
	}
	if !h.isWatchdogBlocked("vpn1") || !hasWatchdogBlock(loadWatchdogBlocked(h.dataDir), "vpn1") {
		t.Fatal("watchdog trip did not durably block vpn1 from automation")
	}
}

// A trip for a session that is already gone (the user turned it off, or a
// reconnect replaced it) must leave the tunnel alone.
func TestForcedDisconnectStaleSessionIsIgnored(t *testing.T) {
	h := newPendingTestHelper(t, "vpn1")
	h.activeCfgs["vpn1"] = &domain.WireGuardConfig{Name: "vpn1"}
	h.persistDesiredState()

	stale := func() bool { return false }
	h.handleForcedDisconnect(tunnel.NewForcedDisconnect("vpn1", "utun9", "routing loop detected", stale))

	if _, ok := h.activeCfgs["vpn1"]; !ok {
		t.Fatal("vpn1 dropped for a stale trip")
	}
	if got := loadDesiredState(h.dataDir); len(got) != 1 || got[0] != "vpn1" {
		t.Fatalf("desired state = %v; want [vpn1]", got)
	}
	if h.isWatchdogBlocked("vpn1") {
		t.Fatal("stale watchdog trip blocked the new session")
	}
}

func hasWatchdogBlock(blocked map[string]struct{}, name string) bool {
	_, ok := blocked[name]
	return ok
}

// The last tunnel going down must leave an automation block on disk. A new
// helper must refuse a rule-driven reconnect until a manual Connect succeeds.
func TestForcedDisconnectBlocksAutomationAfterRestart(t *testing.T) {
	h := newPendingTestHelper(t, "vpn1")
	h.activeCfgs["vpn1"] = &domain.WireGuardConfig{Name: "vpn1"}
	h.persistDesiredState()
	h.handleForcedDisconnect(tunnel.NewForcedDisconnect("vpn1", "utun9", "possible routing loop", nil))

	if got := loadDesiredState(h.dataDir); len(got) != 0 {
		t.Fatalf("desired tunnels after trip = %v; want none", got)
	}
	restarted := newPendingTestHelper(t, "vpn1")
	restarted.dataDir = h.dataDir
	restarted.watchdogBlocked = loadWatchdogBlocked(restarted.dataDir)
	if !restarted.isWatchdogBlocked("vpn1") {
		t.Fatal("watchdog block was lost on helper restart")
	}
	// A blocked automationConnect must return before it reaches the Manager.
	restarted.manager = nil
	restarted.automationConnect("vpn1", "ssid-change", "test")

	// Manual Connect acknowledges the trip and allows future automation.
	restarted.activeCfgs["vpn1"] = &domain.WireGuardConfig{Name: "vpn1"}
	restarted.clearWatchdogBlockHeld("vpn1")
	if restarted.isWatchdogBlocked("vpn1") || hasWatchdogBlock(loadWatchdogBlocked(restarted.dataDir), "vpn1") {
		t.Fatal("manual reconnect did not clear the watchdog block")
	}
}

// A helper may crash after recording the watchdog block but before the
// tunnel has been removed from the desired-state snapshot. That snapshot
// must never restore the blocked tunnel.
func TestRestoreSkipsWatchdogBlockedDesiredTunnel(t *testing.T) {
	h := newPendingTestHelper(t, "vpn1")
	if err := saveDesiredIntent(h.dataDir, desiredStateJSON{
		Tunnels: []string{"vpn1"}, WatchdogBlocked: []string{"vpn1"},
	}); err != nil {
		t.Fatal(err)
	}
	h.watchdogBlocked = loadWatchdogBlocked(h.dataDir)
	h.restoreDesiredTunnels()
	if got := loadDesiredState(h.dataDir); len(got) != 0 {
		t.Fatalf("blocked tunnel restored from desired state: %v", got)
	}
	if !hasWatchdogBlock(loadWatchdogBlocked(h.dataDir), "vpn1") {
		t.Fatal("restore dropped the watchdog block")
	}
}

func TestPreviousBootClearsDesiredTunnelsButKeepsWatchdogBlock(t *testing.T) {
	h := newPendingTestHelper(t, "vpn1", "vpn2")
	if err := saveDesiredIntent(h.dataDir, desiredStateJSON{
		Tunnels: []string{"vpn2"}, WatchdogBlocked: []string{"vpn1"},
	}); err != nil {
		t.Fatal(err)
	}
	h.watchdogBlocked = loadWatchdogBlocked(h.dataDir)
	stale := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(h.dataDir, desiredStateFile), stale, stale); err != nil {
		t.Fatal(err)
	}
	restoreBootTimeStub(t, func() (time.Time, error) { return time.Now().Add(-time.Minute), nil })
	h.restoreDesiredTunnels()
	if got := loadDesiredState(h.dataDir); len(got) != 0 {
		t.Fatalf("previous-boot desired tunnels remained: %v", got)
	}
	if !hasWatchdogBlock(loadWatchdogBlocked(h.dataDir), "vpn1") {
		t.Fatal("previous-boot cleanup removed the watchdog block")
	}
}
