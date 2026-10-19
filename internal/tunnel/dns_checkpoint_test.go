package tunnel

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/network"
)

type checkpointNetwork struct {
	mockNetworkManager
	name             string
	dir              string
	snapshot         network.DNSSnapshot
	checkpoint       func(network.DNSSnapshot) error
	beforeCheckpoint func()
	observed         *ActiveTunnelState
	mutated          bool
}

func (n *checkpointNetwork) SetDNSCheckpoint(checkpoint func(network.DNSSnapshot) error) {
	n.checkpoint = checkpoint
}
func (n *checkpointNetwork) SavedDNSSnapshot() network.DNSSnapshot { return n.snapshot }
func (n *checkpointNetwork) SetDNS(string, []string) error {
	if n.beforeCheckpoint != nil {
		n.beforeCheckpoint()
	}
	if n.checkpoint != nil {
		if err := n.checkpoint(n.snapshot); err != nil {
			return err
		}
	}
	for _, state := range LoadActiveState(n.dir) {
		if state.TunnelName == n.name {
			n.observed = state
		}
	}
	n.mutated = true
	return nil
}

func checkpointManager(t *testing.T, nets ...*checkpointNetwork) *Manager {
	t.Helper()
	dir := t.TempDir()
	index := 0
	m := newTestManagerWithDir(&mockNetworkManager{}, func(cfg *domain.WireGuardConfig) (*Engine, error) { return fakeEngine("test-" + cfg.Name), nil }, dir)
	m.netMgrFactory = func() network.NetworkManager {
		n := nets[index]
		index++
		n.dir = dir
		return n
	}
	t.Cleanup(func() { m.DisconnectAll() })
	return m
}

func TestDNSJournalContainsOriginalBeforeMutationAndForEveryTunnel(t *testing.T) {
	original := network.DNSSnapshot{Servers: map[string][]string{"Wi-Fi": {"8.8.8.8"}}, Search: map[string][]string{"Wi-Fi": {"home.test"}}}
	a := &checkpointNetwork{name: "a", snapshot: original}
	b := &checkpointNetwork{name: "b", snapshot: network.DNSSnapshot{Servers: map[string][]string{"Wi-Fi": {"10.1.1.1"}}, Search: map[string][]string{"Wi-Fi": {"vpn-a.test"}}}}
	m := checkpointManager(t, a, b)
	for _, n := range []*checkpointNetwork{a, b} {
		if err := m.Connect(globalCfg(n.name)); err != nil {
			t.Fatal(err)
		}
		if n.observed == nil || !reflect.DeepEqual(n.observed.PreModDNS, original.Servers) || !reflect.DeepEqual(n.observed.PreModSearch, original.Search) {
			t.Errorf("%s: exact original DNS was not journaled before mutation: %+v", n.name, n.observed)
		}
	}
	for _, state := range LoadActiveState(m.dataDir) {
		if !reflect.DeepEqual(state.PreModDNS, original.Servers) || !reflect.DeepEqual(state.PreModSearch, original.Search) {
			t.Errorf("%s: crash journal recorded another tunnel's overrides as the original DNS: %+v", state.TunnelName, state)
		}
	}
}

func TestDNSJournalFailurePreventsMutation(t *testing.T) {
	n := &checkpointNetwork{name: "a", snapshot: network.DNSSnapshot{Servers: map[string][]string{"Wi-Fi": {"8.8.8.8"}}}}
	m := checkpointManager(t, n)
	n.beforeCheckpoint = func() {
		path := filepath.Join(m.dataDir, tunnelStatesDir, stateFileName(n.name))
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Connect(globalCfg(n.name)); err == nil {
		t.Fatal("connect succeeded although its DNS checkpoint could not be saved")
	}
	if n.mutated {
		t.Fatal("DNS was modified without a durable recovery snapshot")
	}
	if _, captured := m.PreModDNSSnapshot(); captured {
		t.Fatal("failed first connect left a stale baseline for the next session")
	}
}

func TestDNSCheckpointExtendsOnlyNewServices(t *testing.T) {
	m := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), t.TempDir())
	state := ActiveTunnelState{TunnelName: "a", DNSMode: DNSModeGlobal}
	if err := m.persistDNSCheckpoint(state, network.DNSSnapshot{
		Servers: map[string][]string{"Wi-Fi": {"8.8.8.8"}},
		Search:  map[string][]string{"Wi-Fi": nil},
	}); err != nil {
		t.Fatal(err)
	}
	state.TunnelName = "b"
	if err := m.persistDNSCheckpoint(state, network.DNSSnapshot{
		Servers: map[string][]string{"Wi-Fi": {"10.1.1.1"}, "Ethernet": {"9.9.9.9"}},
		Search:  map[string][]string{"Wi-Fi": {"vpn-a.test"}, "Ethernet": {"home.test"}},
	}); err != nil {
		t.Fatal(err)
	}
	baseline, _ := m.PreModDNSSnapshot()
	if !reflect.DeepEqual(baseline.Servers, map[string][]string{"Wi-Fi": {"8.8.8.8"}, "Ethernet": {"9.9.9.9"}}) || len(baseline.Search["Wi-Fi"]) != 0 ||
		!reflect.DeepEqual(baseline.Search["Ethernet"], []string{"home.test"}) {
		t.Fatalf("checkpoint replaced a known original or dropped a new service: %+v", baseline)
	}
}
