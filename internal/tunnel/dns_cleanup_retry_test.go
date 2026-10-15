package tunnel

import (
	"errors"
	"testing"
	"time"

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
