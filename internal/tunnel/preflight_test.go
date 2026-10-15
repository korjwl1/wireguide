package tunnel

import (
	"errors"
	"testing"

	"github.com/korjwl1/wireguide/internal/network"
)

type unsupportedDNSNetwork struct{ *mockNetworkManager }

func (*unsupportedDNSNetwork) ValidateDNSConfig([]string) error {
	return network.ErrSplitDNSUnsupported
}

func TestPreflightRejectsUnsupportedDNSWithoutNetworkChanges(t *testing.T) {
	n := &unsupportedDNSNetwork{&mockNetworkManager{}}
	m := NewManager(t.TempDir())
	m.netMgrFactory = func() network.NetworkManager { return n }
	if err := m.PreflightConnect(splitCfg("unsupported")); !errors.Is(err, network.ErrSplitDNSUnsupported) {
		t.Fatalf("preflight error = %v", err)
	}
	if len(m.AllStatuses()) != 0 || n.addressCalls+n.routeCalls+n.dnsCalls+n.cleanupCalls != 0 {
		t.Fatal("read-only preflight changed network or lifecycle state")
	}
}
