package tunnel

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/network"
)

type restoreRetryNetwork struct {
	mockNetworkManager
	restoreErr error
	restores   int
}

func (n *restoreRetryNetwork) RestoreDNSFromSnapshot(network.DNSSnapshot) error {
	n.restores++
	return n.restoreErr
}

func TestFailedLastDisconnectRetainsBaselineAndJournalUntilRetry(t *testing.T) {
	n := &restoreRetryNetwork{restoreErr: errors.New("DNS write denied")}
	m := newTestManagerWithDir(&n.mockNetworkManager, succeedingFactory(), t.TempDir())
	m.netMgrFactory = func() network.NetworkManager { return n }
	if err := m.Connect(globalCfg("retry")); err != nil {
		t.Fatal(err)
	}
	m.CapturePreModDNS(network.DNSSnapshot{Servers: map[string][]string{"Wi-Fi": {"192.0.2.1"}}})
	if err := m.DisconnectTunnel("retry"); err != nil {
		t.Fatal(err)
	}
	if len(LoadActiveState(m.dataDir)) != 1 {
		t.Fatal("failed restore discarded crash journal")
	}
	if _, ok := m.PreModDNSSnapshot(); !ok {
		t.Fatal("failed restore discarded original DNS")
	}
	if n.cleanupCalls != 1 {
		t.Fatal("failed exact restore fell back to a polluted adapter snapshot")
	}
	n.restoreErr = nil
	m.RetryPendingDNSCleanupAt(time.Now().Add(time.Minute))
	if len(LoadActiveState(m.dataDir)) != 0 {
		t.Fatal("successful retry left crash journal")
	}
	if _, ok := m.PreModDNSSnapshot(); ok {
		t.Fatal("successful retry left baseline")
	}
}

type unionTrackingNetwork struct {
	mockNetworkManager
	policy []string
}

func (n *unionTrackingNetwork) TrackDNSUnion(entries []string) {
	n.policy = append([]string(nil), entries...)
}
func TestGlobalDNSMonitorsShareUnionAcrossConnectAndDisconnect(t *testing.T) {
	a, b := &unionTrackingNetwork{}, &unionTrackingNetwork{}
	m := newTestManagerWithDir(&a.mockNetworkManager, succeedingFactory(), t.TempDir())
	count := 0
	m.netMgrFactory = func() network.NetworkManager {
		count++
		if count == 1 {
			return a
		}
		return b
	}
	defer m.DisconnectAll()
	first, second := globalCfg("a"), globalCfg("b")
	second.Interface.DNS = []string{"9.9.9.9"}
	if err := m.Connect(first); err != nil {
		t.Fatal(err)
	}
	if err := m.Connect(second); err != nil {
		t.Fatal(err)
	}
	if len(a.policy) != 2 {
		t.Fatalf("first monitor retained stale policy: %v", a.policy)
	}
	if err := m.DisconnectTunnel("b"); err != nil {
		t.Fatal(err)
	}
	if len(a.policy) != 1 || a.policy[0] != "1.1.1.1" {
		t.Fatalf("surviving monitor retained removed DNS: %v", a.policy)
	}
}

// An unfixable retired cleanup must neither disable future connections nor let
// a same-named new session overwrite its durable original-DNS journal.
func TestPermanentCleanupFailurePreservesRetiredJournalAndAllowsReconnect(t *testing.T) {
	old := &restoreRetryNetwork{restoreErr: errors.New("removed network service")}
	current := &mockNetworkManager{}
	nextInterface := 0
	m := newTestManagerWithDir(&old.mockNetworkManager, func(*domain.WireGuardConfig) (*Engine, error) {
		nextInterface++
		return fakeEngine(fmt.Sprintf("utun%d", nextInterface)), nil
	}, t.TempDir())
	m.netMgrFactory = func() network.NetworkManager { return old }
	var warnings int
	m.SetOnRecoveryWarning(func(string, error) { warnings++ })
	if err := m.Connect(globalCfg("same")); err != nil {
		t.Fatal(err)
	}
	baseline := network.DNSSnapshot{Servers: map[string][]string{"Wi-Fi": {"192.0.2.1"}}}
	m.CapturePreModDNS(baseline)
	if err := m.DisconnectTunnel("same"); err != nil {
		t.Fatal(err)
	}
	if warnings != 1 {
		t.Fatal("retained recovery was not surfaced")
	}
	m.netMgrFactory = func() network.NetworkManager { return current }
	if err := m.Connect(globalCfg("same")); err != nil {
		t.Fatalf("permanent old cleanup blocked reconnect: %v", err)
	}
	states := LoadActiveState(m.dataDir)
	if len(states) != 2 {
		t.Fatalf("new session overwrote retired journal: %+v", states)
	}
	retired := false
	for _, state := range states {
		if state.journalKey != "" {
			retired = true
		}
	}
	if !retired {
		t.Fatal("retired journal identity was lost on disk")
	}
	oldAttempts := old.restores
	m.RetryPendingDNSCleanupAt(time.Now().Add(time.Hour))
	if old.restores != oldAttempts {
		t.Fatal("retired cleanup touched a live session")
	}
	if err := m.DisconnectTunnel("same"); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.PreModDNSSnapshot(); !ok {
		t.Fatal("new session cleared a baseline still needed by retired cleanup")
	}
	old.restoreErr = nil
	m.RetryPendingDNSCleanupAt(time.Now().Add(time.Hour))
	if len(LoadActiveState(m.dataDir)) != 0 {
		t.Fatal("successful old cleanup retained a journal")
	}
}

func TestCrashRecoveryClearsRetiredJournalByFileIdentity(t *testing.T) {
	dir := t.TempDir()
	state := &ActiveTunnelState{TunnelName: "profile", journalKey: ".cleanup-fixture"}
	if err := SaveActiveState(dir, state); err != nil {
		t.Fatal(err)
	}
	loaded := LoadActiveState(dir)
	if len(loaded) != 1 || loaded[0].journalKey != state.journalKey {
		t.Fatal("retired identity was not restored")
	}
	RecoverFromCrash(dir, nil)
	if len(LoadActiveState(dir)) != 0 {
		t.Fatal("recovery cleared profile name instead of retired journal")
	}
}

func TestFailedStartupRecoveryPreservesBaselineForNewSession(t *testing.T) {
	dir := t.TempDir()
	original := map[string][]string{"Wi-Fi": {"192.0.2.1"}}
	if err := SaveActiveState(dir, &ActiveTunnelState{TunnelName: "same", PreModDNS: original}); err != nil {
		t.Fatal(err)
	}
	m := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), dir)
	m.AdoptPendingRecovery()
	if snapshot, ok := m.PreModDNSSnapshot(); !ok || snapshot.Servers["Wi-Fi"][0] != "192.0.2.1" {
		t.Fatal("failed startup baseline was replaced")
	}
	if err := m.Connect(globalCfg("same")); err != nil {
		t.Fatal(err)
	}
	if len(LoadActiveState(dir)) != 2 {
		t.Fatal("startup cleanup record overwritten by new session")
	}
	m.DisconnectAll()
	m.RetryPendingDNSCleanupAt(time.Now().Add(time.Hour))
	if len(LoadActiveState(dir)) != 0 {
		t.Fatal("startup cleanup record not retried")
	}
}

func TestEarlyConnectFailureRetainsCleanupJournal(t *testing.T) {
	adapter := &mockNetworkManager{setMTUErr: errors.New("MTU failed"), removeRoutesErr: errors.New("route cleanup failed")}
	manager := newTestManagerWithDir(adapter, succeedingFactory(), t.TempDir())
	if err := manager.Connect(testConfig("early")); err == nil {
		t.Fatal("connect failure hidden")
	}
	states := LoadActiveState(manager.dataDir)
	if len(states) != 1 || states[0].journalKey == "" {
		t.Fatal("early rollback lost durable interface ownership")
	}
	if needsDNSReset(states[0]) {
		t.Fatal("failure before DNS would reset untouched DNS")
	}
}
