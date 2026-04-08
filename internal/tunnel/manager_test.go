package tunnel

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
)

// ---------------------------------------------------------------------------
// Mock NetworkManager
// ---------------------------------------------------------------------------

// mockNetworkManager implements network.NetworkManager with configurable
// behaviour for each method. By default every method succeeds (returns nil).
// Tests override individual fields to inject failures or record calls.
type mockNetworkManager struct {
	assignAddressErr error
	setMTUErr        error
	bringUpErr       error
	addRoutesErr     error
	removeRoutesErr  error
	setDNSErr        error
	restoreDNSErr    error
	cleanupErr       error

	// Call tracking
	mu           sync.Mutex
	mtuCalls     int
	addressCalls int
	bringUpCalls int
	routeCalls   int
	dnsCalls     int
	cleanupCalls int
}

func (m *mockNetworkManager) AssignAddress(string, []string) error {
	m.mu.Lock()
	m.addressCalls++
	m.mu.Unlock()
	return m.assignAddressErr
}

func (m *mockNetworkManager) SetMTU(string, int) error {
	m.mu.Lock()
	m.mtuCalls++
	m.mu.Unlock()
	return m.setMTUErr
}

func (m *mockNetworkManager) BringUp(string) error {
	m.mu.Lock()
	m.bringUpCalls++
	m.mu.Unlock()
	return m.bringUpErr
}

func (m *mockNetworkManager) AddRoutes(string, []string, bool, []string, string, string) error {
	m.mu.Lock()
	m.routeCalls++
	m.mu.Unlock()
	return m.addRoutesErr
}

func (m *mockNetworkManager) RemoveRoutes(string, []string, bool) error {
	m.mu.Lock()
	m.cleanupCalls++ // counts as cleanup-related
	m.mu.Unlock()
	return m.removeRoutesErr
}

func (m *mockNetworkManager) SetDNS(string, []string) error {
	m.mu.Lock()
	m.dnsCalls++
	m.mu.Unlock()
	return m.setDNSErr
}

func (m *mockNetworkManager) RestoreDNS(string) error      { return m.restoreDNSErr }
func (m *mockNetworkManager) ResetDNSToSystemDefault() error { return nil }
func (m *mockNetworkManager) Cleanup(string) error {
	m.mu.Lock()
	m.cleanupCalls++
	m.mu.Unlock()
	return m.cleanupErr
}

// ---------------------------------------------------------------------------
// Mock Engine factory
// ---------------------------------------------------------------------------

// fakeEngine creates a minimal Engine with the given interface name. It has
// no TUN device or wireguard-go device, so Close() is a no-op. This is safe
// because the Manager never talks to the engine directly — it only passes
// it to the NetworkManager methods (which are also mocked).
func fakeEngine(name string) *Engine {
	return &Engine{
		ifaceName:           name,
		resolvedEndpointIPs: []string{"1.2.3.4"},
		resolvedEndpoints:   []string{"1.2.3.4:51820"},
	}
}

// succeedingFactory returns an engineFactory that always succeeds.
func succeedingFactory() func(*domain.WireGuardConfig) (*Engine, error) {
	return func(*domain.WireGuardConfig) (*Engine, error) {
		return fakeEngine("utun42"), nil
	}
}

// failingFactory returns an engineFactory that always fails.
func failingFactory(err error) func(*domain.WireGuardConfig) (*Engine, error) {
	return func(*domain.WireGuardConfig) (*Engine, error) {
		return nil, err
	}
}

// slowFactory returns an engineFactory that blocks for the given duration
// before succeeding. Useful for testing concurrent access and disconnect
// timeout behaviour.
func slowFactory(d time.Duration) func(*domain.WireGuardConfig) (*Engine, error) {
	return func(*domain.WireGuardConfig) (*Engine, error) {
		time.Sleep(d)
		return fakeEngine("utun42"), nil
	}
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestManagerWithDir creates a test manager with an explicit data dir.
func newTestManagerWithDir(netMgr *mockNetworkManager, factory func(*domain.WireGuardConfig) (*Engine, error), dataDir string) *Manager {
	return &Manager{
		netMgr:        netMgr,
		dataDir:       dataDir,
		tunnels:       make(map[string]*tunnelEntry),
		engineFactory: factory,
	}
}

func testConfig(name string) *domain.WireGuardConfig {
	return &domain.WireGuardConfig{
		Name: name,
		Interface: domain.InterfaceConfig{
			PrivateKey: "not-used-in-tests",
			Address:    []string{"10.0.0.2/24"},
		},
		Peers: []domain.PeerConfig{
			{
				PublicKey:   "not-used-in-tests",
				AllowedIPs:  []string{"10.0.0.0/24"},
				Endpoint:    "1.2.3.4:51820",
			},
		},
	}
}

func assertTunnelError(t *testing.T, err error, wantKind ErrorKind) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var te *TunnelError
	if !errors.As(err, &te) {
		t.Fatalf("expected *TunnelError, got %T: %v", err, err)
	}
	if te.Kind != wantKind {
		t.Fatalf("expected ErrorKind %d, got %d (%s)", wantKind, te.Kind, te.Message)
	}
}

// tunnelState returns the state of a named tunnel, or StateDisconnected if not found.
func tunnelState(m *Manager, name string) domain.State {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.tunnels[name]
	if !ok {
		return domain.StateDisconnected
	}
	return e.state
}

// tunnelEngine returns the engine for a named tunnel, or nil if not found.
func tunnelEngine(m *Manager, name string) *Engine {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.tunnels[name]
	if !ok {
		return nil
	}
	return e.engine
}

// tunnelConnectedAt returns the connectedAt time for a named tunnel.
func tunnelConnectedAt(m *Manager, name string) time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.tunnels[name]
	if !ok {
		return time.Time{}
	}
	return e.connectedAt
}

// setTunnelState sets the state of a named tunnel directly (for test setup).
func setTunnelState(m *Manager, name string, state domain.State) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.getOrCreateEntry(name)
	e.state = state
}

// setTunnelEntry sets up a tunnel entry directly (for test setup).
func setTunnelEntry(m *Manager, name string, state domain.State, cfg *domain.WireGuardConfig, engine *Engine) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.getOrCreateEntry(name)
	e.state = state
	e.cfg = cfg
	e.engine = engine
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestConnect_Success(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	if err := mgr.Connect(testConfig("vpn1")); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if tunnelState(mgr, "vpn1") != domain.StateConnected {
		t.Fatalf("expected state connected, got %s", tunnelState(mgr, "vpn1"))
	}
	if !mgr.IsConnected() {
		t.Fatal("IsConnected should be true after successful Connect")
	}
	if mgr.ActiveTunnel() != "vpn1" {
		t.Fatalf("ActiveTunnel = %q, want %q", mgr.ActiveTunnel(), "vpn1")
	}
	if tunnelEngine(mgr, "vpn1") == nil {
		t.Fatal("engine should be non-nil after Connect")
	}
	if tunnelConnectedAt(mgr, "vpn1").IsZero() {
		t.Fatal("connectedAt should be set after Connect")
	}
}

func TestConnect_AlreadyConnected(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	if err := mgr.Connect(testConfig("vpn1")); err != nil {
		t.Fatalf("first Connect failed: %v", err)
	}

	// Same tunnel name should fail with AlreadyConnected.
	err := mgr.Connect(testConfig("vpn1"))
	assertTunnelError(t, err, ErrAlreadyConnected)

	// State should remain connected to the original tunnel.
	if mgr.ActiveTunnel() != "vpn1" {
		t.Fatalf("ActiveTunnel should still be vpn1, got %q", mgr.ActiveTunnel())
	}
}

func TestConnect_DifferentTunnels(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	if err := mgr.Connect(testConfig("vpn1")); err != nil {
		t.Fatalf("first Connect failed: %v", err)
	}

	// Different tunnel name should succeed (multi-tunnel support).
	if err := mgr.Connect(testConfig("vpn2")); err != nil {
		t.Fatalf("second Connect failed: %v", err)
	}

	if !mgr.IsTunnelConnected("vpn1") {
		t.Fatal("vpn1 should still be connected")
	}
	if !mgr.IsTunnelConnected("vpn2") {
		t.Fatal("vpn2 should be connected")
	}

	tunnels := mgr.ActiveTunnels()
	if len(tunnels) != 2 {
		t.Fatalf("expected 2 active tunnels, got %d: %v", len(tunnels), tunnels)
	}
}

func TestConnect_TransitionInProgress(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	// Use a slow factory so the first Connect is still running when we try the second.
	mgr := newTestManagerWithDir(net, slowFactory(500*time.Millisecond), dir)

	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- mgr.Connect(testConfig("vpn1"))
	}()

	<-started
	// Give the goroutine time to enter connecting state.
	time.Sleep(50 * time.Millisecond)

	// Same name should get TransitionInProgress.
	err := mgr.Connect(testConfig("vpn1"))
	assertTunnelError(t, err, ErrTransitionInProgress)

	// Wait for the first Connect to finish.
	if err := <-done; err != nil {
		t.Fatalf("first Connect failed: %v", err)
	}
}

func TestConnect_EngineCreationFailure_RollsBackToDisconnected(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	engineErr := errors.New("TUN creation failed")
	mgr := newTestManagerWithDir(net, failingFactory(engineErr), dir)

	err := mgr.Connect(testConfig("vpn1"))
	if err == nil {
		t.Fatal("expected error from Connect")
	}

	// Verify the error wraps the engine creation failure.
	var te *TunnelError
	if !errors.As(err, &te) {
		t.Fatalf("expected *TunnelError, got %T", err)
	}
	if te.Kind != ErrEngineCreation {
		t.Fatalf("expected ErrEngineCreation, got %d", te.Kind)
	}

	// State should roll back — entry should be removed entirely.
	if tunnelState(mgr, "vpn1") != domain.StateDisconnected {
		t.Fatalf("expected disconnected after failure, got %s", tunnelState(mgr, "vpn1"))
	}
	if mgr.IsConnected() {
		t.Fatal("IsConnected should be false after failed Connect")
	}
	if mgr.ActiveTunnel() != "" {
		t.Fatalf("ActiveTunnel should be empty after failed Connect, got %q", mgr.ActiveTunnel())
	}
}

func TestConnect_NetworkPhaseFailure_RollsBack(t *testing.T) {
	// Test that a failure in a network phase (e.g. SetMTU) rolls back properly.
	dir := t.TempDir()
	net := &mockNetworkManager{
		setMTUErr: errors.New("MTU failed"),
	}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	err := mgr.Connect(testConfig("vpn1"))
	assertTunnelError(t, err, ErrNetwork)

	if tunnelState(mgr, "vpn1") != domain.StateDisconnected {
		t.Fatalf("expected disconnected after network failure, got %s", tunnelState(mgr, "vpn1"))
	}
}

func TestConnect_AddressFailure_RollsBack(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{
		assignAddressErr: errors.New("address failed"),
	}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	err := mgr.Connect(testConfig("vpn1"))
	assertTunnelError(t, err, ErrNetwork)

	if tunnelState(mgr, "vpn1") != domain.StateDisconnected {
		t.Fatalf("expected disconnected, got %s", tunnelState(mgr, "vpn1"))
	}
}

func TestConnect_BringUpFailure_RollsBack(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{
		bringUpErr: errors.New("bring up failed"),
	}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	err := mgr.Connect(testConfig("vpn1"))
	assertTunnelError(t, err, ErrNetwork)

	if tunnelState(mgr, "vpn1") != domain.StateDisconnected {
		t.Fatalf("expected disconnected, got %s", tunnelState(mgr, "vpn1"))
	}
}

func TestConnect_AddRoutesFailure_RollsBack(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{
		addRoutesErr: errors.New("routes failed"),
	}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	err := mgr.Connect(testConfig("vpn1"))
	assertTunnelError(t, err, ErrNetwork)

	if tunnelState(mgr, "vpn1") != domain.StateDisconnected {
		t.Fatalf("expected disconnected, got %s", tunnelState(mgr, "vpn1"))
	}
}

func TestConnect_DNSFailure_FatalWhenServersConfigured(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{
		setDNSErr: errors.New("dns failed"),
	}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	cfg := testConfig("vpn1")
	cfg.Interface.DNS = []string{"1.1.1.1"}

	err := mgr.Connect(cfg)
	assertTunnelError(t, err, ErrNetwork)

	if tunnelState(mgr, "vpn1") != domain.StateDisconnected {
		t.Fatalf("expected disconnected, got %s", tunnelState(mgr, "vpn1"))
	}
}

func TestConnect_DNSFailure_NonFatalWhenNoServers(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{
		setDNSErr: errors.New("dns failed"),
	}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	cfg := testConfig("vpn1")
	cfg.Interface.DNS = nil // no DNS servers configured

	// Should succeed despite DNS error — it's non-fatal when no servers configured.
	if err := mgr.Connect(cfg); err != nil {
		t.Fatalf("Connect should succeed when DNS fails with no servers: %v", err)
	}
	if tunnelState(mgr, "vpn1") != domain.StateConnected {
		t.Fatalf("expected connected, got %s", tunnelState(mgr, "vpn1"))
	}
}

func TestDisconnect_Success(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	if err := mgr.Connect(testConfig("vpn1")); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if err := mgr.Disconnect(); err != nil {
		t.Fatalf("Disconnect failed: %v", err)
	}

	if tunnelState(mgr, "vpn1") != domain.StateDisconnected {
		t.Fatalf("expected disconnected, got %s", tunnelState(mgr, "vpn1"))
	}
	if mgr.IsConnected() {
		t.Fatal("IsConnected should be false after Disconnect")
	}
	if mgr.ActiveTunnel() != "" {
		t.Fatalf("ActiveTunnel should be empty, got %q", mgr.ActiveTunnel())
	}
}

func TestDisconnect_NotConnected(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	err := mgr.Disconnect()
	assertTunnelError(t, err, ErrNotConnected)
}

func TestDisconnect_WaitsForConnectToFinish(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	// Connect takes 300ms to complete.
	mgr := newTestManagerWithDir(net, slowFactory(300*time.Millisecond), dir)

	connectDone := make(chan error, 1)
	go func() {
		connectDone <- mgr.Connect(testConfig("vpn1"))
	}()

	// Wait for connecting state.
	time.Sleep(50 * time.Millisecond)

	// Disconnect should wait for Connect to finish, then disconnect.
	if err := mgr.Disconnect(); err != nil {
		t.Fatalf("Disconnect failed: %v", err)
	}

	// Connect should also have succeeded.
	if err := <-connectDone; err != nil {
		// Connect may have succeeded or gotten ErrStateCorrupt if Disconnect
		// changed state while it was in-flight. Either is acceptable.
		var te *TunnelError
		if errors.As(err, &te) && te.Kind != ErrStateCorrupt {
			t.Fatalf("unexpected Connect error: %v", err)
		}
	}

	if tunnelState(mgr, "vpn1") != domain.StateDisconnected {
		t.Fatalf("expected disconnected, got %s", tunnelState(mgr, "vpn1"))
	}
}

func TestDisconnect_TimeoutWhenConnectNeverFinishes(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	// Connect blocks for 30s — longer than the 10s timeout.
	mgr := newTestManagerWithDir(net, slowFactory(30*time.Second), dir)

	go func() {
		mgr.Connect(testConfig("vpn1"))
	}()

	// Wait for connecting state.
	time.Sleep(50 * time.Millisecond)

	// Test with a manager stuck in connecting state directly.
	mgr2 := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), dir)
	setTunnelEntry(mgr2, "vpn1", domain.StateConnecting, testConfig("vpn1"), nil)

	start := time.Now()
	err := mgr2.DisconnectTunnel("vpn1")
	elapsed := time.Since(start)

	assertTunnelError(t, err, ErrTimeout)

	// Should have waited roughly 10 seconds.
	if elapsed < 9*time.Second {
		t.Fatalf("expected ~10s timeout, got %v", elapsed)
	}
}

func TestStatus_Disconnected(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	status := mgr.Status()
	if status.State != domain.StateDisconnected {
		t.Fatalf("expected disconnected, got %s", status.State)
	}
	if status.TunnelName != "" {
		t.Fatalf("expected empty tunnel name, got %q", status.TunnelName)
	}
}

func TestStatus_Connecting(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	mgr := newTestManagerWithDir(net, slowFactory(500*time.Millisecond), dir)

	go func() {
		mgr.Connect(testConfig("vpn1"))
	}()

	// Wait for connecting state.
	time.Sleep(50 * time.Millisecond)

	status := mgr.Status()
	if status.State != domain.StateConnecting {
		t.Fatalf("expected connecting, got %s", status.State)
	}
	if status.TunnelName != "vpn1" {
		t.Fatalf("expected tunnel name vpn1, got %q", status.TunnelName)
	}
}

func TestStatus_Disconnecting(t *testing.T) {
	// Verify that disconnecting state surfaces as "connecting" (the GUI
	// doesn't distinguish them).
	dir := t.TempDir()
	mgr := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), dir)

	// Set state directly to disconnecting.
	setTunnelEntry(mgr, "vpn1", stateDisconnecting, testConfig("vpn1"), nil)

	status := mgr.Status()
	if status.State != domain.StateConnecting {
		t.Fatalf("expected connecting (for disconnecting), got %s", status.State)
	}
	if status.TunnelName != "vpn1" {
		t.Fatalf("expected tunnel name vpn1, got %q", status.TunnelName)
	}
}

func TestStatus_ErrorState(t *testing.T) {
	dir := t.TempDir()
	mgr := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), dir)

	setTunnelEntry(mgr, "vpn-err", domain.StateError, testConfig("vpn-err"), nil)

	status := mgr.Status()
	if status.State != domain.StateError {
		t.Fatalf("expected error, got %s", status.State)
	}
	if status.TunnelName != "vpn-err" {
		t.Fatalf("expected tunnel name vpn-err, got %q", status.TunnelName)
	}
}

func TestStatus_ConnectedWithNilEngine(t *testing.T) {
	// Edge case: state is connected but engine is nil (should not happen in
	// practice, but the code guards against it).
	dir := t.TempDir()
	mgr := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), dir)

	setTunnelEntry(mgr, "vpn1", domain.StateConnected, testConfig("vpn1"), nil)

	status := mgr.Status()
	// Should fall back to disconnected rather than panic.
	if status.State != domain.StateDisconnected {
		t.Fatalf("expected disconnected fallback, got %s", status.State)
	}
}

func TestIsConnected_AllStates(t *testing.T) {
	dir := t.TempDir()
	mgr := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), dir)

	tests := []struct {
		state domain.State
		want  bool
	}{
		{domain.StateDisconnected, false},
		{domain.StateConnecting, false},
		{domain.StateConnected, true},
		{domain.StateError, false},
		{stateDisconnecting, false},
	}

	for _, tt := range tests {
		// Reset tunnels
		mgr.mu.Lock()
		mgr.tunnels = make(map[string]*tunnelEntry)
		if tt.state != domain.StateDisconnected {
			mgr.tunnels["test"] = &tunnelEntry{state: tt.state}
		}
		mgr.mu.Unlock()

		got := mgr.IsConnected()
		if got != tt.want {
			t.Errorf("IsConnected() with state %q = %v, want %v", tt.state, got, tt.want)
		}
	}
}

func TestActiveTunnel_NilConfig(t *testing.T) {
	dir := t.TempDir()
	mgr := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), dir)

	if name := mgr.ActiveTunnel(); name != "" {
		t.Fatalf("expected empty, got %q", name)
	}
}

func TestActiveTunnel_DuringConnecting(t *testing.T) {
	dir := t.TempDir()
	mgr := newTestManagerWithDir(&mockNetworkManager{}, slowFactory(500*time.Millisecond), dir)

	go func() {
		mgr.Connect(testConfig("test-vpn"))
	}()

	time.Sleep(50 * time.Millisecond)

	if name := mgr.ActiveTunnel(); name != "test-vpn" {
		t.Fatalf("expected test-vpn during connecting, got %q", name)
	}
}

func TestResolvedEndpointIPs_NoEngine(t *testing.T) {
	dir := t.TempDir()
	mgr := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), dir)

	if ips := mgr.ResolvedEndpointIPs(); ips != nil {
		t.Fatalf("expected nil, got %v", ips)
	}
}

func TestResolvedEndpoints_NoEngine(t *testing.T) {
	dir := t.TempDir()
	mgr := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), dir)

	if eps := mgr.ResolvedEndpoints(); eps != nil {
		t.Fatalf("expected nil, got %v", eps)
	}
}

func TestResolvedEndpointIPs_WithEngine(t *testing.T) {
	dir := t.TempDir()
	mgr := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), dir)

	if err := mgr.Connect(testConfig("vpn1")); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	ips := mgr.ResolvedEndpointIPs()
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Fatalf("expected [1.2.3.4], got %v", ips)
	}
}

func TestResolvedEndpoints_WithEngine(t *testing.T) {
	dir := t.TempDir()
	mgr := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), dir)

	if err := mgr.Connect(testConfig("vpn1")); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	eps := mgr.ResolvedEndpoints()
	if len(eps) != 1 || eps[0] != "1.2.3.4:51820" {
		t.Fatalf("expected [1.2.3.4:51820], got %v", eps)
	}
}

func TestConcurrentConnect_RaceDetection(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)

	var successCount atomic.Int32
	var alreadyConnected atomic.Int32
	var transitionInProgress atomic.Int32

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			err := mgr.Connect(testConfig("vpn1"))
			if err == nil {
				successCount.Add(1)
				return
			}
			var te *TunnelError
			if errors.As(err, &te) {
				switch te.Kind {
				case ErrAlreadyConnected:
					alreadyConnected.Add(1)
				case ErrTransitionInProgress:
					transitionInProgress.Add(1)
				}
			}
		}(i)
	}
	wg.Wait()

	// Exactly one Connect should succeed.
	if s := successCount.Load(); s != 1 {
		t.Fatalf("expected exactly 1 success, got %d", s)
	}

	// All others should get AlreadyConnected or TransitionInProgress.
	total := successCount.Load() + alreadyConnected.Load() + transitionInProgress.Load()
	if total != goroutines {
		t.Fatalf("expected %d total outcomes, got %d (success=%d, already=%d, transition=%d)",
			goroutines, total, successCount.Load(), alreadyConnected.Load(), transitionInProgress.Load())
	}
}

func TestConnectDisconnect_FullCycle(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	// Cycle through connect/disconnect multiple times.
	for i := 0; i < 3; i++ {
		if err := mgr.Connect(testConfig("vpn1")); err != nil {
			t.Fatalf("cycle %d: Connect failed: %v", i, err)
		}
		if !mgr.IsConnected() {
			t.Fatalf("cycle %d: expected connected", i)
		}
		if err := mgr.Disconnect(); err != nil {
			t.Fatalf("cycle %d: Disconnect failed: %v", i, err)
		}
		if mgr.IsConnected() {
			t.Fatalf("cycle %d: expected disconnected", i)
		}
	}
}

func TestDisconnect_NilEngine_StateCorrupt(t *testing.T) {
	// Test the guard against engine being nil when state is Connected.
	dir := t.TempDir()
	mgr := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), dir)

	setTunnelEntry(mgr, "vpn1", domain.StateConnected, testConfig("vpn1"), nil)

	err := mgr.DisconnectTunnel("vpn1")
	assertTunnelError(t, err, ErrStateCorrupt)

	// State should be reset to disconnected (entry removed).
	if tunnelState(mgr, "vpn1") != domain.StateDisconnected {
		t.Fatalf("expected disconnected, got %s", tunnelState(mgr, "vpn1"))
	}
}

func TestConnect_DisconnectingState_RejectsConnect(t *testing.T) {
	// If state is "disconnecting", Connect should return ErrTransitionInProgress.
	dir := t.TempDir()
	mgr := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), dir)

	setTunnelState(mgr, "vpn1", stateDisconnecting)

	err := mgr.Connect(testConfig("vpn1"))
	assertTunnelError(t, err, ErrTransitionInProgress)
}

func TestConnect_SetsActiveCfgDuringConnecting(t *testing.T) {
	// Verify that cfg is set BEFORE the engine factory runs, so that
	// Status()/ActiveTunnel() can show the tunnel name during connecting.
	dir := t.TempDir()
	net := &mockNetworkManager{}

	var capturedName string
	var mgr *Manager
	factory := func(cfg *domain.WireGuardConfig) (*Engine, error) {
		// While inside the factory (simulating slow engine creation),
		// check that ActiveTunnel() returns the name.
		capturedName = mgr.ActiveTunnel()
		return fakeEngine("utun42"), nil
	}

	mgr = newTestManagerWithDir(net, factory, dir)

	if err := mgr.Connect(testConfig("my-tunnel")); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if capturedName != "my-tunnel" {
		t.Fatalf("expected ActiveTunnel = my-tunnel during connecting, got %q", capturedName)
	}
}

// ---------------------------------------------------------------------------
// Multi-tunnel tests
// ---------------------------------------------------------------------------

func TestDisconnectTunnel_Specific(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	if err := mgr.Connect(testConfig("vpn1")); err != nil {
		t.Fatalf("Connect vpn1 failed: %v", err)
	}
	if err := mgr.Connect(testConfig("vpn2")); err != nil {
		t.Fatalf("Connect vpn2 failed: %v", err)
	}

	// Disconnect only vpn1.
	if err := mgr.DisconnectTunnel("vpn1"); err != nil {
		t.Fatalf("DisconnectTunnel vpn1 failed: %v", err)
	}

	if mgr.IsTunnelConnected("vpn1") {
		t.Fatal("vpn1 should be disconnected")
	}
	if !mgr.IsTunnelConnected("vpn2") {
		t.Fatal("vpn2 should still be connected")
	}
}

func TestDisconnectAll(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	if err := mgr.Connect(testConfig("vpn1")); err != nil {
		t.Fatalf("Connect vpn1 failed: %v", err)
	}
	if err := mgr.Connect(testConfig("vpn2")); err != nil {
		t.Fatalf("Connect vpn2 failed: %v", err)
	}

	mgr.DisconnectAll()

	if mgr.IsConnected() {
		t.Fatal("no tunnels should be connected after DisconnectAll")
	}
	if len(mgr.ActiveTunnels()) != 0 {
		t.Fatalf("expected 0 active tunnels, got %v", mgr.ActiveTunnels())
	}
}

func TestActiveTunnels_Sorted(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	if err := mgr.Connect(testConfig("z-vpn")); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if err := mgr.Connect(testConfig("a-vpn")); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	tunnels := mgr.ActiveTunnels()
	if len(tunnels) != 2 {
		t.Fatalf("expected 2 tunnels, got %d", len(tunnels))
	}
	if tunnels[0] != "a-vpn" || tunnels[1] != "z-vpn" {
		t.Fatalf("expected sorted [a-vpn, z-vpn], got %v", tunnels)
	}
}

func TestIsTunnelConnected(t *testing.T) {
	dir := t.TempDir()
	net := &mockNetworkManager{}
	mgr := newTestManagerWithDir(net, succeedingFactory(), dir)

	if mgr.IsTunnelConnected("vpn1") {
		t.Fatal("vpn1 should not be connected initially")
	}

	if err := mgr.Connect(testConfig("vpn1")); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if !mgr.IsTunnelConnected("vpn1") {
		t.Fatal("vpn1 should be connected")
	}
	if mgr.IsTunnelConnected("vpn2") {
		t.Fatal("vpn2 should not be connected")
	}
}

func TestStatusFor(t *testing.T) {
	dir := t.TempDir()
	mgr := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), dir)

	// Not connected — should return disconnected.
	status := mgr.StatusFor("vpn1")
	if status.State != domain.StateDisconnected {
		t.Fatalf("expected disconnected, got %s", status.State)
	}

	// Connect.
	setTunnelEntry(mgr, "vpn1", domain.StateConnecting, testConfig("vpn1"), nil)
	status = mgr.StatusFor("vpn1")
	if status.State != domain.StateConnecting {
		t.Fatalf("expected connecting, got %s", status.State)
	}
}

func TestResolvedEndpoints_MultiTunnel(t *testing.T) {
	dir := t.TempDir()
	mgr := newTestManagerWithDir(&mockNetworkManager{}, succeedingFactory(), dir)

	if err := mgr.Connect(testConfig("vpn1")); err != nil {
		t.Fatalf("Connect vpn1 failed: %v", err)
	}
	if err := mgr.Connect(testConfig("vpn2")); err != nil {
		t.Fatalf("Connect vpn2 failed: %v", err)
	}

	ips := mgr.ResolvedEndpointIPs()
	if len(ips) != 2 {
		t.Fatalf("expected 2 endpoint IPs, got %d: %v", len(ips), ips)
	}

	eps := mgr.ResolvedEndpoints()
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %d: %v", len(eps), eps)
	}
}
