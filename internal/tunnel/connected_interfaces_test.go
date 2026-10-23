package tunnel

import (
	"github.com/korjwl1/wireguide/internal/domain"
	"testing"
)

func TestFirewallSnapshotSurvivesUnavailableTelemetry(t *testing.T) {
	m := NewManager(t.TempDir())
	setTunnelEntry(m, "live", domain.StateConnected, testConfig("live"), fakeEngine("audit999"))
	st := m.AllStatuses()
	if len(st) != 1 || st[0].State != domain.StateError {
		t.Fatalf("expected unavailable device telemetry, got %+v", st)
	}
	live := m.ConnectedInterfaces()
	if len(live) != 1 || live[0].State != domain.StateConnected || live[0].InterfaceName != "audit999" {
		t.Fatalf("telemetry failure erased live interface: %+v", live)
	}
	m.mu.Lock()
	m.tunnels["live"].state = domain.StateDisconnected
	m.mu.Unlock()
	if len(m.ConnectedInterfaces()) != 0 {
		t.Fatal("real lifecycle disconnect retained a permit")
	}
}
