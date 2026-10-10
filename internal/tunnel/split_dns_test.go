package tunnel

import (
	"errors"
	"sync"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/network"
)

func init() {
	// Recovery tests must never drive the host's real network services or
	// dynamic store.
	newRecoveryManager = func() network.NetworkManager { return &recoveryMock{} }
	cleanupStaleSplitDNS = func() error { return nil }
}

// splitMock records SetDNS arguments and RemoveSplitDNS calls on top of the
// shared mockNetworkManager.
type splitMock struct {
	*mockNetworkManager
	smu       sync.Mutex
	dnsArgs   [][]string
	removed   []string
	setDNSErr error
}

func (s *splitMock) SetDNS(_ string, entries []string) error {
	s.smu.Lock()
	s.dnsArgs = append(s.dnsArgs, append([]string(nil), entries...))
	s.smu.Unlock()
	return s.setDNSErr
}

func (s *splitMock) RemoveSplitDNS(iface string) error {
	s.smu.Lock()
	s.removed = append(s.removed, iface)
	s.smu.Unlock()
	return nil
}

func (s *splitMock) removedCount() int {
	s.smu.Lock()
	defer s.smu.Unlock()
	return len(s.removed)
}

func newSplitManager(s *splitMock, dir string) *Manager {
	return &Manager{
		dataDir:       dir,
		tunnels:       make(map[string]*tunnelEntry),
		netMgrFactory: func() network.NetworkManager { return s },
		engineFactory: succeedingFactory(),
	}
}

func splitCfg(name string) *domain.WireGuardConfig {
	cfg := testConfig(name)
	cfg.Interface.DNS = []string{"10.1.1.1", "~corp.lan"}
	return cfg
}

func globalCfg(name string) *domain.WireGuardConfig {
	cfg := testConfig(name)
	cfg.Interface.DNS = []string{"1.1.1.1"}
	return cfg
}

func TestSplitConnectSkipsUnionAndRecordsMode(t *testing.T) {
	s := &splitMock{mockNetworkManager: &mockNetworkManager{}}
	dir := t.TempDir()
	mgr := newSplitManager(s, dir)

	if err := mgr.Connect(globalCfg("g")); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Connect(splitCfg("s")); err != nil {
		t.Fatal(err)
	}
	last := s.dnsArgs[len(s.dnsArgs)-1]
	if len(last) != 2 || last[0] != "10.1.1.1" || last[1] != "~corp.lan" {
		t.Fatalf("split SetDNS got %v, want only its own entries (no global union)", last)
	}
	modes := map[string]string{}
	for _, st := range LoadActiveState(dir) {
		modes[st.TunnelName] = st.DNSMode
	}
	if modes["s"] != DNSModeSplit || modes["g"] != DNSModeGlobal {
		t.Fatalf("journal modes = %v", modes)
	}
}

func TestGlobalConnectExcludesSplitTunnelEntries(t *testing.T) {
	s := &splitMock{mockNetworkManager: &mockNetworkManager{}}
	mgr := newSplitManager(s, t.TempDir())

	if err := mgr.Connect(splitCfg("s")); err != nil {
		t.Fatal(err)
	}
	if got := mgr.AllDNSServers(); len(got) != 0 {
		t.Fatalf("AllDNSServers = %v, want split tunnel excluded", got)
	}
	if err := mgr.Connect(globalCfg("g")); err != nil {
		t.Fatal(err)
	}
	last := s.dnsArgs[len(s.dnsArgs)-1]
	if len(last) != 1 || last[0] != "1.1.1.1" {
		t.Fatalf("global SetDNS got %v, want [1.1.1.1]", last)
	}
}

func TestSplitDisconnectRemovesKeysWhileGlobalRemains(t *testing.T) {
	s := &splitMock{mockNetworkManager: &mockNetworkManager{}}
	mgr := newSplitManager(s, t.TempDir())
	if err := mgr.Connect(globalCfg("g")); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Connect(splitCfg("s")); err != nil {
		t.Fatal(err)
	}
	before := len(s.dnsArgs)
	if err := mgr.DisconnectTunnel("s"); err != nil {
		t.Fatal(err)
	}
	if s.removedCount() == 0 {
		t.Fatal("RemoveSplitDNS not called on split disconnect with a global tunnel remaining")
	}
	if len(s.dnsArgs) != before {
		t.Fatalf("split disconnect re-applied global DNS: %v", s.dnsArgs[before:])
	}
}

func TestGlobalDisconnectReapplyPicksNonSplitTunnel(t *testing.T) {
	s := &splitMock{mockNetworkManager: &mockNetworkManager{}}
	mgr := newSplitManager(s, t.TempDir())
	g1, g2 := globalCfg("g1"), globalCfg("g2")
	g2.Interface.DNS = []string{"9.9.9.9"}
	for _, c := range []*domain.WireGuardConfig{g1, splitCfg("s"), g2} {
		if err := mgr.Connect(c); err != nil {
			t.Fatal(err)
		}
	}
	before := len(s.dnsArgs)
	if err := mgr.DisconnectTunnel("g1"); err != nil {
		t.Fatal(err)
	}
	if len(s.dnsArgs) != before+1 {
		t.Fatalf("expected one re-apply, got %v", s.dnsArgs[before:])
	}
	got := s.dnsArgs[before]
	if len(got) != 1 || got[0] != "9.9.9.9" {
		t.Fatalf("re-apply got %v, want [9.9.9.9]", got)
	}
}

func TestSplitUnsupportedIsNonFatal(t *testing.T) {
	s := &splitMock{mockNetworkManager: &mockNetworkManager{}, setDNSErr: network.ErrSplitDNSUnsupported}
	mgr := newSplitManager(s, t.TempDir())
	if err := mgr.Connect(splitCfg("s")); err != nil {
		t.Fatalf("ErrSplitDNSUnsupported must not fail connect: %v", err)
	}
	if !mgr.IsTunnelConnected("s") {
		t.Fatal("tunnel should be connected")
	}
}

func TestSplitOtherErrorRollsBackAndClearsJournal(t *testing.T) {
	s := &splitMock{mockNetworkManager: &mockNetworkManager{}, setDNSErr: errors.New("scutil blew up")}
	dir := t.TempDir()
	mgr := newSplitManager(s, dir)
	err := mgr.Connect(splitCfg("s"))
	assertTunnelError(t, err, ErrNetwork)
	if s.removedCount() == 0 {
		t.Fatal("rollback did not call RemoveSplitDNS")
	}
	if n := len(LoadActiveState(dir)); n != 0 {
		t.Fatalf("rollback left %d journal(s)", n)
	}
}

// --- recovery ---

type recoveryMock struct {
	mockNetworkManager
	resetCalls int
	restored   int
	cleaned    []string
}

func (r *recoveryMock) ResetDNSToSystemDefault() error { r.resetCalls++; return nil }
func (r *recoveryMock) Cleanup(iface string) error     { r.cleaned = append(r.cleaned, iface); return nil }

func runRecovery(t *testing.T, st *ActiveTunnelState) *recoveryMock {
	t.Helper()
	mock := &recoveryMock{}
	old := newRecoveryManager
	newRecoveryManager = func() network.NetworkManager { return mock }
	defer func() { newRecoveryManager = old }()
	dir := t.TempDir()
	if err := SaveActiveState(dir, st); err != nil {
		t.Fatal(err)
	}
	RecoverFromCrash(dir, nil)
	return mock
}

func TestRecoveryResetsDNSOnlyForGlobalJournals(t *testing.T) {
	tests := []struct {
		name      string
		st        ActiveTunnelState
		wantReset int
	}{
		{"global", ActiveTunnelState{TunnelName: "a", InterfaceName: "utun5", DNSMode: DNSModeGlobal, DNSServers: []string{"1.1.1.1"}}, 1},
		{"legacy with dns", ActiveTunnelState{TunnelName: "a", InterfaceName: "utun5", DNSServers: []string{"1.1.1.1"}}, 1},
		{"split", ActiveTunnelState{TunnelName: "a", InterfaceName: "utun5", DNSMode: DNSModeSplit, DNSServers: []string{"10.1.1.1", "~x.lan"}}, 0},
		{"no dns", ActiveTunnelState{TunnelName: "a", InterfaceName: "utun5"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := tt.st
			mock := runRecovery(t, &st)
			if mock.resetCalls != tt.wantReset {
				t.Fatalf("ResetDNSToSystemDefault calls = %d, want %d", mock.resetCalls, tt.wantReset)
			}
			if len(mock.cleaned) != 1 || mock.cleaned[0] != "utun5" {
				t.Fatalf("Cleanup calls = %v, want [utun5] (removes split keys)", mock.cleaned)
			}
		})
	}
}

func TestRecoverFromCrashSweepsSplitKeysWithoutJournal(t *testing.T) {
	calls := 0
	old := cleanupStaleSplitDNS
	cleanupStaleSplitDNS = func() error { calls++; return nil }
	defer func() { cleanupStaleSplitDNS = old }()
	RecoverFromCrash(t.TempDir(), nil)
	if calls != 1 {
		t.Fatalf("sweep calls = %d, want 1", calls)
	}
}
