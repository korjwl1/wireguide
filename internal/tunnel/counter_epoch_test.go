package tunnel

import (
	"context"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
)

func TestManagerPublishesStableDistinctCounterEpochs(t *testing.T) {
	factory := func(*domain.WireGuardConfig) (*Engine, error) {
		return &Engine{kernel: &fakeKernelBackend{}, ifaceName: "test-kernel"}, nil
	}
	m := newTestManagerWithDir(&mockNetworkManager{}, factory, t.TempDir())
	previous := ""
	for round := 0; round < 2; round++ {
		if err := m.ConnectWithContext(context.Background(), testConfig("vpn")); err != nil {
			t.Fatal(err)
		}
		epoch := m.Status().CounterEpoch
		if epoch == "" || epoch == previous {
			t.Fatalf("epoch missing or reused: %q", epoch)
		}
		for _, status := range []*ConnectionStatus{m.Status(), m.StatusFor("vpn"), m.AllStatuses()[0]} {
			if status.CounterEpoch != epoch {
				t.Fatalf("status views disagree: %+v", status)
			}
		}
		setTunnelState(m, "vpn", domain.StateConnecting)
		for _, status := range []*ConnectionStatus{m.Status(), m.StatusFor("vpn"), m.AllStatuses()[0]} {
			if status.CounterEpoch != "" {
				t.Fatalf("transition leaked an engine epoch: %+v", status)
			}
		}
		setTunnelState(m, "vpn", domain.StateConnected)
		if err := m.DisconnectTunnel("vpn"); err != nil {
			t.Fatal(err)
		}
		if m.StatusFor("vpn").CounterEpoch != "" {
			t.Fatal("disconnected status leaked an epoch")
		}
		previous = epoch
	}
}
