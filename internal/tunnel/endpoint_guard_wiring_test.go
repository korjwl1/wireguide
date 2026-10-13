package tunnel

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/network"
)

type guardedNetworkManager struct {
	*mockNetworkManager
	guard   func(bool)
	check   func() (string, error)
	dnsSets [][]string
}

func (m *guardedNetworkManager) SetEndpointTrafficGuard(guard func(bool)) { m.guard = guard }
func (m *guardedNetworkManager) EndpointRoutingLoop([]string) (string, error) {
	return m.check()
}

func (m *guardedNetworkManager) SetDNS(iface string, servers []string) error {
	m.mu.Lock()
	m.dnsSets = append(m.dnsSets, append([]string(nil), servers...))
	m.mu.Unlock()
	return m.mockNetworkManager.SetDNS(iface, servers)
}

func TestConnectDoesNotOverrideRouteRepairTrafficGate(t *testing.T) {
	guard := &routeGuardBind{allowed: true}
	netMgr := &guardedNetworkManager{mockNetworkManager: &mockNetworkManager{}}
	netMgr.check = func() (string, error) {
		// The initial verification allows traffic under the route lock.
		netMgr.guard(true)
		// A route repair can acquire that lock and pause traffic before
		// connectPhases resumes. The connection must respect its decision.
		netMgr.guard(false)
		return "", nil
	}
	mgr := newTestManagerWithDir(netMgr.mockNetworkManager, func(*domain.WireGuardConfig) (*Engine, error) {
		e := fakeEngine("utun42")
		// Preserve the Windows test binder; only the gate itself is shared.
		e.bind = &testGatedBind{guardedBind: e.bind.(*guardedBind), gate: guard}
		return e, nil
	}, t.TempDir())
	mgr.netMgrFactory = func() network.NetworkManager { return netMgr }
	if err := mgr.Connect(testConfig("guarded")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.DisconnectTunnel("guarded") })
	guard.mu.RLock()
	allowed := guard.allowed
	guard.mu.RUnlock()
	if allowed {
		t.Fatal("connection completion overrode an ongoing route repair's traffic block")
	}
}

type testGatedBind struct {
	*guardedBind
	gate *routeGuardBind
}

func (b *testGatedBind) SetEndpointTrafficAllowed(allow bool) {
	b.gate.SetEndpointTrafficAllowed(allow)
}

func TestEndpointVerificationFailureRollsBackBeforeDNS(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason string
		err    error
	}{
		{name: "recursive route", reason: "endpoint routes through its own tunnel"},
		{name: "unknown route", err: errors.New("route query failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			netMgr := &guardedNetworkManager{mockNetworkManager: &mockNetworkManager{}}
			netMgr.check = func() (string, error) { return tc.reason, tc.err }
			dir := t.TempDir()
			mgr := newTestManagerWithDir(netMgr.mockNetworkManager, succeedingFactory(), dir)
			mgr.netMgrFactory = func() network.NetworkManager { return netMgr }
			protector := &mockEndpointProtector{}
			mgr.SetEndpointProtector(protector)
			cfg := testFullTunnelConfig("rejected")
			cfg.Interface.DNS = []string{"10.0.0.1"}
			assertTunnelError(t, mgr.Connect(cfg), ErrNetwork)
			if tunnelState(mgr, cfg.Name) != domain.StateDisconnected {
				t.Fatal("failed verification left a connected tunnel")
			}
			if netMgr.dnsCalls != 0 {
				t.Fatal("failed verification modified DNS")
			}
			wantRoutes := []string{"0.0.0.0/0", "::/0"}
			if !reflect.DeepEqual(netMgr.removedRoutes, wantRoutes) || netMgr.cleanupCalls != 2 {
				t.Fatalf("rollback incomplete: routes=%v cleanup calls=%d", netMgr.removedRoutes, netMgr.cleanupCalls)
			}
			if protector.enableCallCount() != 1 || protector.disableCallCount() != 1 {
				t.Fatal("failed verification leaked endpoint firewall protection")
			}
			if len(LoadActiveState(dir)) != 0 {
				t.Fatal("failed verification left an active tunnel journal")
			}
		})
	}
}

func TestEndpointGuardsPreserveOtherTunnelAndDNSOnReconnect(t *testing.T) {
	var nets []*guardedNetworkManager
	var gates []*routeGuardBind
	mgr := newTestManagerWithDir(nil, func(*domain.WireGuardConfig) (*Engine, error) {
		e := fakeEngine(fmt.Sprintf("utun%d", len(gates)+40))
		gate := &routeGuardBind{allowed: true}
		gates = append(gates, gate)
		e.bind = &testGatedBind{guardedBind: e.bind.(*guardedBind), gate: gate}
		return e, nil
	}, t.TempDir())
	mgr.netMgrFactory = func() network.NetworkManager {
		nm := &guardedNetworkManager{mockNetworkManager: &mockNetworkManager{}}
		nm.check = func() (string, error) { nm.guard(true); return "", nil }
		nets = append(nets, nm)
		return nm
	}
	t.Cleanup(mgr.DisconnectAll)
	protector := &mockEndpointProtector{}
	mgr.SetEndpointProtector(protector)
	alpha, bravo := testFullTunnelConfig("alpha"), testConfig("bravo")
	alpha.Interface.DNS = []string{"10.0.0.1"}
	bravo.Interface.DNS = []string{"10.1.0.1"}
	if err := mgr.Connect(alpha); err != nil {
		t.Fatal(err)
	}
	// Pausing one tunnel's outer traffic must not be undone by another
	// tunnel connecting or by DNS/firewall updates for that tunnel.
	nets[0].guard(false)
	if err := mgr.Connect(bravo); err != nil {
		t.Fatal(err)
	}
	if gates[0].allowed || !gates[1].allowed {
		t.Fatal("traffic gates were shared between tunnels")
	}
	if want := []string{"10.1.0.1", "10.0.0.1"}; !reflect.DeepEqual(nets[1].dnsSets[0], want) {
		t.Fatalf("second tunnel DNS = %v, want %v", nets[1].dnsSets, want)
	}
	if err := mgr.DisconnectTunnel("alpha"); err != nil {
		t.Fatal(err)
	}
	if tunnelState(mgr, "bravo") != domain.StateConnected || len(nets[1].removedRoutes) != 0 || !gates[1].allowed {
		t.Fatal("disconnecting alpha changed bravo's connection, routes or traffic gate")
	}
	if got := nets[1].dnsSets[len(nets[1].dnsSets)-1]; !reflect.DeepEqual(got, bravo.Interface.DNS) {
		t.Fatalf("DNS after alpha disconnect = %v, want %v", got, bravo.Interface.DNS)
	}
	if protector.disableCallCount() != 1 || protector.disableCalls[0] != "utun40" {
		t.Fatal("disconnect removed the wrong tunnel's endpoint firewall filters")
	}
	if err := mgr.Connect(alpha); err != nil {
		t.Fatal(err)
	}
	if !gates[2].allowed || gates[0].allowed {
		t.Fatal("reconnect reused the previous session's traffic gate")
	}
	if want := []string{"10.0.0.1", "10.1.0.1"}; !reflect.DeepEqual(nets[2].dnsSets[0], want) {
		t.Fatalf("reconnected tunnel DNS = %v, want %v", nets[2].dnsSets, want)
	}
}
