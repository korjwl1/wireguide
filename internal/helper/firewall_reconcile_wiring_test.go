package helper

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// fakeFW is a recording FirewallManager that also implements DNSPermitSetter.
type fakeFW struct {
	ks          bool
	permits     []firewall.DNSPermit
	setCalls    [][]firewall.DNSPermit
	ksCalls     []string
	failSetOnce bool
}

func (f *fakeFW) EnableKillSwitch(iface string, _ []string, _ []string) error {
	f.ks = true
	f.ksCalls = append(f.ksCalls, "enable:"+iface)
	return nil
}
func (f *fakeFW) AddKillSwitchTunnel(iface string, _ []string, _ []string) error {
	f.ksCalls = append(f.ksCalls, "add:"+iface)
	return nil
}
func (f *fakeFW) RemoveKillSwitchTunnel(iface string) error {
	f.ksCalls = append(f.ksCalls, "remove:"+iface)
	return nil
}
func (f *fakeFW) DisableKillSwitch() error {
	f.ks = false
	f.ksCalls = append(f.ksCalls, "disable")
	return nil
}
func (f *fakeFW) EnableEndpointProtection(string, []string) error { return nil }
func (f *fakeFW) DisableEndpointProtection(string) error          { return nil }
func (f *fakeFW) EnableDNSProtection(string, []string) error      { return nil }
func (f *fakeFW) DisableDNSProtection() error                     { return nil }
func (f *fakeFW) IsKillSwitchEnabled() bool                       { return f.ks }
func (f *fakeFW) IsDNSProtectionEnabled() bool                    { return len(f.permits) > 0 }
func (f *fakeFW) Cleanup() error                                  { return nil }
func (f *fakeFW) RecoverFromCrash() bool                          { return false }
func (f *fakeFW) SetDNSPermits(p []firewall.DNSPermit) error {
	f.setCalls = append(f.setCalls, p)
	if f.failSetOnce {
		f.failSetOnce = false
		return errors.New("injected")
	}
	f.permits = p
	return nil
}

func newWiringHelper(t *testing.T, fw firewall.FirewallManager) *Helper {
	t.Helper()
	return &Helper{
		manager:    tunnel.NewManager(t.TempDir()),
		firewall:   fw,
		activeCfgs: map[string]*domain.WireGuardConfig{},
	}
}

func TestSafetyNetRetriesFailedReconcileWithZeroTunnels(t *testing.T) {
	fw := &fakeFW{permits: []firewall.DNSPermit{{Interface: "utun4", Server: "10.0.0.1"}}, failSetOnce: true}
	h := newWiringHelper(t, fw)

	h.connectMu.Lock()
	err := h.reconcileFirewallErrLocked("test")
	h.connectMu.Unlock()
	if err == nil {
		t.Fatal("expected the injected failure")
	}
	if h.reconciledKey != reconcileDirtyKey {
		t.Fatalf("failed reconcile must not be recorded as handled, key=%q", h.reconciledKey)
	}

	// Within the backoff window the tick must not retry.
	n := len(fw.setCalls)
	h.maybeReconcileOnTunnelChange()
	if len(fw.setCalls) != n {
		t.Fatal("retry must wait for the backoff")
	}

	// After the backoff the tick retries and clears the stale permits even
	// though the (empty) tunnel set never changed.
	h.reconcileRetryAt = time.Now().Add(-time.Second)
	h.maybeReconcileOnTunnelChange()
	if len(fw.permits) != 0 {
		t.Fatalf("stale DNS permits not cleared by retry: %+v", fw.permits)
	}
	if h.reconciledKey == reconcileDirtyKey {
		t.Fatal("successful retry must record the real key")
	}
}

func TestSuspendResumeZeroTunnelsRestoresBaseKillSwitchNoDNS(t *testing.T) {
	fw := &fakeFW{ks: true, permits: []firewall.DNSPermit{{Interface: "utun4", Server: "10.0.0.1"}}}
	h := newWiringHelper(t, fw)
	h.dnsWanted = true

	if err := h.suspendFirewall(); err != nil {
		t.Fatal(err)
	}
	if fw.ks || len(fw.permits) != 0 {
		t.Fatalf("suspend must clear kill switch and DNS: ks=%v permits=%v", fw.ks, fw.permits)
	}
	// Nested suspension: only the last resume reconciles.
	if err := h.suspendFirewall(); err != nil {
		t.Fatal(err)
	}
	fw.ksCalls = nil
	if err := h.resumeFirewall(); err != nil {
		t.Fatal(err)
	}
	if len(fw.ksCalls) != 0 {
		t.Fatalf("inner resume must not reconcile: %v", fw.ksCalls)
	}
	if err := h.resumeFirewall(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fw.ksCalls, []string{"enable:"}) {
		t.Fatalf("expected base kill switch restored, got %v", fw.ksCalls)
	}
	if len(fw.permits) != 0 {
		t.Fatalf("no DNS rule may exist with zero tunnels: %v", fw.permits)
	}
}

func TestApplyDNSLockedCachesUnchangedSet(t *testing.T) {
	fw := &fakeFW{}
	h := newWiringHelper(t, fw)
	h.connectMu.Lock()
	defer h.connectMu.Unlock()
	snap := h.snapshotConnected()
	if err := h.applyDNSLocked("a", snap); err != nil {
		t.Fatal(err)
	}
	if err := h.applyDNSLocked("b", snap); err != nil {
		t.Fatal(err)
	}
	if len(fw.setCalls) != 1 {
		t.Fatalf("unchanged set must be applied once, got %d calls", len(fw.setCalls))
	}
}

func TestLegacyDNSArgs(t *testing.T) {
	tun := []reconcileTunnel{rt("a", "wg0", nil)}
	tests := []struct {
		name    string
		permits []firewall.DNSPermit
		tunnels []reconcileTunnel
		iface   string
		servers []string
	}{
		{"pinned", []firewall.DNSPermit{{Interface: "wg1", Server: "10.0.0.1"}}, tun, "wg1", []string{"10.0.0.1"}},
		{"unpinned falls back to first tunnel", []firewall.DNSPermit{{Server: "1.1.1.1"}}, tun, "wg0", []string{"1.1.1.1"}},
		{"duplicate servers collapse", []firewall.DNSPermit{{Interface: "wg0", Server: "1.1.1.1"}, {Server: "1.1.1.1"}}, tun, "wg0", []string{"1.1.1.1"}},
		{"no tunnels", []firewall.DNSPermit{{Server: "1.1.1.1"}}, nil, "", []string{"1.1.1.1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface, servers := legacyDNSArgs(tt.permits, tt.tunnels)
			if iface != tt.iface || !reflect.DeepEqual(servers, tt.servers) {
				t.Fatalf("got %q %v want %q %v", iface, servers, tt.iface, tt.servers)
			}
		})
	}
}

func TestReconcileBackoff(t *testing.T) {
	if reconcileBackoff(1) != 2*time.Second || reconcileBackoff(2) != 4*time.Second {
		t.Fatal("backoff should start at 2s and double")
	}
	if reconcileBackoff(50) != time.Minute {
		t.Fatal("backoff must cap at 60s")
	}
}
