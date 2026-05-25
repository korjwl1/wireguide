package tunnel

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
)

// mockEndpointProtector records calls into the EndpointProtector
// interface so tests can assert the exact connect/disconnect ordering
// and content. Default-constructed: every method returns nil.
type mockEndpointProtector struct {
	mu sync.Mutex

	enableCalls  []endpointProtectorCall
	disableCalls []string

	enableErr  error
	disableErr error
}

type endpointProtectorCall struct {
	iface     string
	endpoints []string
}

func (m *mockEndpointProtector) EnableEndpointProtection(iface string, endpoints []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]string, len(endpoints))
	copy(cp, endpoints)
	m.enableCalls = append(m.enableCalls, endpointProtectorCall{iface: iface, endpoints: cp})
	return m.enableErr
}

func (m *mockEndpointProtector) DisableEndpointProtection(iface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disableCalls = append(m.disableCalls, iface)
	return m.disableErr
}

func (m *mockEndpointProtector) enableCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.enableCalls)
}

func (m *mockEndpointProtector) disableCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.disableCalls)
}

func TestEndpointProtector_FullTunnel_EnableThenDisable(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	prot := &mockEndpointProtector{}

	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)
	mgr.SetEndpointProtector(prot)

	cfg := testFullTunnelConfig("fulltun")
	if err := mgr.Connect(cfg); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if got := prot.enableCallCount(); got != 1 {
		t.Fatalf("EnableEndpointProtection: got %d calls, want 1", got)
	}
	prot.mu.Lock()
	enableCall := prot.enableCalls[0]
	prot.mu.Unlock()
	if enableCall.iface == "" {
		t.Fatalf("EnableEndpointProtection called with empty iface")
	}

	if err := mgr.DisconnectTunnel("fulltun"); err != nil {
		t.Fatalf("Disconnect failed: %v", err)
	}
	if got := prot.disableCallCount(); got != 1 {
		t.Fatalf("DisableEndpointProtection: got %d calls, want 1", got)
	}
}

func TestEndpointProtector_SplitTunnel_NotCalled(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	prot := &mockEndpointProtector{}

	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)
	mgr.SetEndpointProtector(prot)

	// testConfig returns a split-tunnel config (AllowedIPs = 10.0.0.0/24).
	if err := mgr.Connect(testConfig("split")); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if got := prot.enableCallCount(); got != 0 {
		t.Fatalf("Split tunnel must not Enable endpoint protection; got %d calls", got)
	}
	// Disable is still called on disconnect for symmetry (idempotent
	// on the implementation side — see DisableEndpointProtection's
	// "no-op when no filters tracked" contract).
	if err := mgr.DisconnectTunnel("split"); err != nil {
		t.Fatalf("Disconnect failed: %v", err)
	}
	if got := prot.disableCallCount(); got != 1 {
		t.Fatalf("Disable should be called once on disconnect even for split (idempotent); got %d", got)
	}
}

func TestEndpointProtector_EnableFailure_RollsBack(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	prot := &mockEndpointProtector{
		enableErr: errors.New("simulated WFP failure"),
	}

	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)
	mgr.SetEndpointProtector(prot)

	err := mgr.Connect(testFullTunnelConfig("fulltun"))
	if err == nil {
		t.Fatal("Connect should fail when endpoint protection fails")
	}
	if tunnelState(mgr, "fulltun") != domain.StateDisconnected {
		t.Fatalf("expected disconnected after rollback, got %s", tunnelState(mgr, "fulltun"))
	}

	// Rollback must call DisableEndpointProtection to clean any state
	// the protector may have managed to record before failing.
	if got := prot.disableCallCount(); got != 1 {
		t.Fatalf("rollback should Disable endpoint protection; got %d calls", got)
	}
}

func TestEndpointProtector_NilProtector_NoCrash(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}

	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)
	// Deliberately do NOT call SetEndpointProtector — the wiring must
	// nil-guard so platforms that don't set one keep working.

	if err := mgr.Connect(testFullTunnelConfig("fulltun")); err != nil {
		t.Fatalf("Connect with nil protector failed: %v", err)
	}
	if err := mgr.DisconnectTunnel("fulltun"); err != nil {
		t.Fatalf("Disconnect with nil protector failed: %v", err)
	}
}

func TestEndpointProtector_EnableCalledBeforeAddRoutes(t *testing.T) {
	// Ordering invariant: endpoint protection must be installed BEFORE
	// AddRoutes is called, because AddRoutes is what arms the routing
	// loop that the protection defends against. We assert this by
	// making AddRoutes fail and verifying the protector saw an Enable
	// (which means Enable came first).
	dir := t.TempDir()
	net := &mockNetworkManager{addRoutesErr: errors.New("simulated AddRoutes failure")}
	prot := &mockEndpointProtector{}

	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)
	mgr.SetEndpointProtector(prot)

	err := mgr.Connect(testFullTunnelConfig("fulltun"))
	if err == nil {
		t.Fatal("Connect should fail when AddRoutes fails")
	}

	// Enable should have been called BEFORE AddRoutes failed — proves
	// our hook is on the correct side of the route install.
	if got := prot.enableCallCount(); got != 1 {
		t.Fatalf("Enable should be called before AddRoutes; got %d calls", got)
	}
	// And Disable should be called as part of the rollback.
	if got := prot.disableCallCount(); got != 1 {
		t.Fatalf("Disable should be called in rollback; got %d calls", got)
	}
}

// TestEndpointProtector_FullTunnelEndpointsForwarded asserts the
// endpoints from the engine make it into the EnableEndpointProtection
// call payload — without this the WFP BLOCK would target zero
// endpoints and the protection would be a no-op even when wired.
func TestEndpointProtector_FullTunnelEndpointsForwarded(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	prot := &mockEndpointProtector{}

	// Build an engine factory that returns an engine with pre-set
	// resolved endpoints (mirrors what NewEngine produces).
	factory := func(_ *domain.WireGuardConfig) (*Engine, error) {
		e := fakeEngine("utun42")
		e.resolvedEndpoints = []string{"203.0.113.10:51820"}
		return e, nil
	}

	mgr := newTestManagerWithDir(net, factory, dir)
	mgr.SetEndpointProtector(prot)

	if err := mgr.Connect(testFullTunnelConfig("fulltun")); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	// Snapshot under the mock's lock, then release before issuing
	// further calls into the manager (which itself calls into the
	// mock and would deadlock against our held lock).
	prot.mu.Lock()
	enableLen := len(prot.enableCalls)
	var firstEndpoints []string
	if enableLen > 0 {
		firstEndpoints = append(firstEndpoints, prot.enableCalls[0].endpoints...)
	}
	prot.mu.Unlock()

	if enableLen != 1 {
		t.Fatalf("expected 1 Enable call, got %d", enableLen)
	}
	if len(firstEndpoints) != 1 || firstEndpoints[0] != "203.0.113.10:51820" {
		t.Fatalf("endpoints forwarded incorrectly: got %v, want [203.0.113.10:51820]", firstEndpoints)
	}

	// Sanity: subsequent disconnect releases everything.
	if err := mgr.DisconnectTunnel("fulltun"); err != nil {
		t.Fatalf("Disconnect failed: %v", err)
	}
	// Give the disconnect a tick to drain any background goroutines
	// the watchdog might have left running; the test's parallel
	// safety doesn't depend on it but it documents expected timing.
	time.Sleep(10 * time.Millisecond)
}
