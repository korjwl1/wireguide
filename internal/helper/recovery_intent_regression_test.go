package helper

import (
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/reconnect"
)

func servedHelper(t *testing.T, names ...string) (*Helper, chan struct{}) {
	h := newPendingTestHelper(t, names...)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.server = ipc.NewServer(ln)
	done := make(chan struct{})
	go func() { _ = h.server.Serve(); close(done) }()
	t.Cleanup(h.server.Shutdown)
	return h, done
}

// R1: idle timer fires while a connect has activeCfgs populated (doConnectHeld
// sets it before manager.Connect). The fire-time check aborts and never re-arms.
// The connect then fails and doConnectHeld rolls activeCfgs back
// (handlers.go rollback branch) WITHOUT calling maybeArmShutdownAfterTeardown.
func TestRecovery_FireAbortDuringConnectThenRollbackNeverShutsDown(t *testing.T) {
	h, done := servedHelper(t)
	h.armShutdownTimer(20*time.Millisecond, "GUI disconnected")
	h.mu.Lock()
	h.activeCfgs["work"] = &domain.WireGuardConfig{Name: "work"} // connect in flight
	h.mu.Unlock()
	time.Sleep(60 * time.Millisecond) // timer fires, sees pending, aborts
	h.mu.Lock()
	delete(h.activeCfgs, "work") // doConnectHeld failure rollback (no re-arm)
	h.mu.Unlock()
	select {
	case <-done:
		t.Log("helper shut down (no defect)")
	case <-time.After(300 * time.Millisecond):
		t.Errorf("DEFECT: no GUI, no tunnel, nothing wanted, but helper never shuts down (timer=%v)", h.shutdownTimer != nil)
	}
}

// Withdrawal must start a fresh idle window, even when no window was armed.
func TestRecovery_WithdrawPendingShutsDown(t *testing.T) {
	h, done := servedHelper(t, "work")
	h.pendingDesired["work"] = struct{}{}
	h.withdrawPendingDesired("work")
	h.mu.Lock()
	timer := h.shutdownTimer
	if timer != nil {
		timer.Reset(20 * time.Millisecond)
	}
	h.mu.Unlock()
	if timer == nil {
		t.Fatal("withdrawal did not arm an idle window")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle helper did not shut down")
	}
}

func TestRecovery_MissingPendingConfigArmsIdleWindow(t *testing.T) {
	h := newPendingTestHelper(t)
	h.pendingDesired["missing"] = struct{}{}
	h.pendingDesiredCfgs()
	h.mu.Lock()
	timer := h.shutdownTimer
	h.mu.Unlock()
	if timer == nil {
		t.Fatal("dropping last missing config did not arm shutdown")
	}
	t.Cleanup(h.cancelShutdownTimer)
}

func TestRecovery_FailedConnectArmsIdleWindow(t *testing.T) {
	h := newPendingTestHelper(t)
	if err := h.doConnectHeld(&domain.WireGuardConfig{Name: "invalid"}); err == nil {
		t.Fatal("expected invalid config failure")
	}
	h.mu.Lock()
	timer := h.shutdownTimer
	h.mu.Unlock()
	if timer == nil {
		t.Fatal("connect rollback did not arm shutdown")
	}
	t.Cleanup(h.cancelShutdownTimer)
}

// R3: explicit DNS Off (config.json false, and even a live SetDNSProtection(false))
// is overridden by the crash-restore intent.
func TestRecovery_RestoreOverridesExplicitDNSOff(t *testing.T) {
	h := newPendingTestHelper(t, "alpha")
	h.userAppSupport = t.TempDir()
	h.logLevel = new(slog.LevelVar)
	h.monitor = reconnect.NewMonitor(h.manager, nil, nil, reconnect.DefaultConfig())
	if err := os.WriteFile(filepath.Join(h.userAppSupport, "config.json"), []byte(`{"dns_protection":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveDesiredIntent(h.dataDir, desiredStateJSON{Tunnels: []string{"alpha"}, DNSProtection: true}); err != nil {
		t.Fatal(err)
	}
	restoreBootTimeStub(t, func() (time.Time, error) { return time.Now().Add(-time.Hour), nil })
	stubRuleSaysOff(t)
	stubRestoreConnect(t)
	h.restoreUserSettings()
	raw, _ := json.Marshal(ipc.DNSProtectionRequest{Enabled: false})
	if _, err := h.handleSetDNSProtection(raw); err != nil {
		t.Fatal(err)
	}
	h.restoreDesiredTunnels()
	if h.dnsProtectionWanted {
		t.Errorf("DEFECT: explicit DNS Off overridden by restore intent; persisted=%+v", loadDesiredIntent(h.dataDir))
	}
}

func dnsRestoreHelper(t *testing.T) *Helper {
	h := newPendingTestHelper(t, "alpha")
	h.userAppSupport = t.TempDir()
	h.logLevel = new(slog.LevelVar)
	h.monitor = reconnect.NewMonitor(h.manager, nil, nil, reconnect.DefaultConfig())
	if err := os.WriteFile(filepath.Join(h.userAppSupport, "config.json"), []byte(`{"dns_protection":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveDesiredIntent(h.dataDir, desiredStateJSON{Tunnels: []string{"alpha"}, DNSProtection: true}); err != nil {
		t.Fatal(err)
	}
	restoreBootTimeStub(t, func() (time.Time, error) { return time.Now().Add(-time.Hour), nil })
	stubRestoreConnect(t)
	return h
}

// R3b: config.json says Off (written by `ctl set dns-protection off` while the
// helper was down; IPC failed). Crash restore re-enables from stale intent.
func TestRecovery_RestoreOverridesConfigDNSOff(t *testing.T) {
	h := dnsRestoreHelper(t)
	stubRuleSaysOff(t)
	h.restoreUserSettings()
	h.restoreDesiredTunnels()
	if h.dnsProtectionWanted {
		t.Errorf("DEFECT: config.json DNS Off overridden by restore intent; persisted=%+v", loadDesiredIntent(h.dataDir))
	}
}

// R3c: live SetDNSProtection(false) lands after restore loaded its intent
// (restore is async and evaluates rules before taking connectMu).
func TestRecovery_RestoreOverridesLiveDNSOff(t *testing.T) {
	h := dnsRestoreHelper(t)
	h.restoreUserSettings()
	prev := restoreRuleSaysOff
	restoreRuleSaysOff = func(hh *Helper, name string) bool {
		raw, _ := json.Marshal(ipc.DNSProtectionRequest{Enabled: false})
		if _, err := hh.handleSetDNSProtection(raw); err != nil {
			t.Error(err)
		}
		return false
	}
	t.Cleanup(func() { restoreRuleSaysOff = prev })
	h.restoreDesiredTunnels()
	if h.dnsProtectionWanted {
		t.Errorf("DEFECT: live DNS Off overridden by in-flight restore; persisted=%+v", loadDesiredIntent(h.dataDir))
	}
}

func TestRecovery_KillSwitchOffWinsOverCrashJournal(t *testing.T) {
	h := newPendingTestHelper(t, "alpha")
	if err := saveDesiredIntent(h.dataDir, desiredStateJSON{Tunnels: []string{"alpha"}, KillSwitch: true}); err != nil {
		t.Fatal(err)
	}
	restoreBootTimeStub(t, func() (time.Time, error) { return time.Now().Add(-time.Hour), nil })
	stubRestoreConnect(t)
	prev := restoreRuleSaysOff
	restoreRuleSaysOff = func(hh *Helper, _ string) bool {
		if _, err := hh.handleSetKillSwitch(json.RawMessage(`{"enabled":false}`)); err != nil {
			t.Error(err)
		}
		return false
	}
	t.Cleanup(func() { restoreRuleSaysOff = prev })
	h.restoreDesiredTunnels()
	if h.killSwitchWanted || loadDesiredIntent(h.dataDir).KillSwitch {
		t.Fatal("restore overrode explicit kill switch Off")
	}
}

func TestRecovery_FullTunnelPreservesDNSOffButNewConnectResetsIt(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsAutoOff = true
	cfg := &domain.WireGuardConfig{Name: "work", Peers: []domain.PeerConfig{{AllowedIPs: []string{"0.0.0.0/0"}}}}
	h.applyConnectedFirewall(cfg, false)
	if !h.dnsAutoOff {
		t.Fatal("recovery erased explicit DNS Off")
	}
	h.applyPostConnectFirewall(cfg)
	if h.dnsAutoOff {
		t.Fatal("new full-tunnel connect no longer resets automatic DNS override")
	}
}

func TestRecovery_StartupRestoreOwnsLifetimeBeforePendingRegistration(t *testing.T) {
	h, done := servedHelper(t)
	if err := saveDesiredState(h.dataDir, []string{"missing"}); err != nil {
		t.Fatal(err)
	}
	restoreBootTimeStub(t, func() (time.Time, error) { return time.Now().Add(-time.Hour), nil })
	entered, release := make(chan struct{}), make(chan struct{})
	prev := restoreRuleSaysOff
	restoreRuleSaysOff = func(*Helper, string) bool { close(entered); <-release; return false }
	finished := make(chan struct{})
	go func() { h.restoreDesiredTunnels(); close(finished) }()
	<-entered
	h.armShutdownTimer(20*time.Millisecond, "startup restore still inspecting rules")
	select {
	case <-done:
		t.Error("helper exited during startup restore")
	case <-time.After(60 * time.Millisecond):
	}
	close(release)
	<-finished
	restoreRuleSaysOff = prev
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("completed empty restore stranded helper")
	}
}
