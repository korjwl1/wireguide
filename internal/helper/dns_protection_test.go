package helper

import (
	"encoding/json"
	"net/netip"
	"slices"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// stubConnected presents the named tunnels as connected on the given
// interfaces, in this order, and caches their configs in activeCfgs.
func stubConnected(t *testing.T, h *Helper, tunnels ...struct {
	name, iface string
	dns         []string
}) {
	t.Helper()
	var statuses []*tunnel.ConnectionStatus
	h.mu.Lock()
	for _, tn := range tunnels {
		cfg := &domain.WireGuardConfig{Name: tn.name}
		cfg.Interface.DNS = tn.dns
		for _, raw := range tn.dns {
			if ip, err := netip.ParseAddr(raw); err == nil {
				cfg.Peers = append(cfg.Peers, domain.PeerConfig{AllowedIPs: []string{netip.PrefixFrom(ip, ip.BitLen()).String()}})
			}
		}
		h.activeCfgs[tn.name] = cfg
		statuses = append(statuses, &tunnel.ConnectionStatus{
			TunnelName: tn.name, InterfaceName: tn.iface, State: domain.StateConnected,
		})
	}
	h.mu.Unlock()
	prev := tunnelStatuses
	tunnelStatuses = func(*Helper) []*tunnel.ConnectionStatus { return statuses }
	t.Cleanup(func() { tunnelStatuses = prev })
}

type tn = struct {
	name, iface string
	dns         []string
}

func dnsFW(h *Helper) *pendingTestFirewall { return h.firewall.(*pendingTestFirewall) }

// Two tunnels up: each tunnel's servers on its own interface, not one
// tunnel's servers on one interface (issue #48).
func TestReapplyDNSProtection_CoversEveryConnectedTunnel(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h,
		tn{"alpha", "utun4", []string{"10.0.0.1"}},
		tn{"bravo", "utun5", []string{"10.1.0.1", "corp.example"}},
		tn{"charlie", "utun6", nil}, // no DNS: contributes nothing
	)

	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	want := []firewall.DNSAllow{
		{Interface: "utun4", Servers: []string{"10.0.0.1"}},
		{Interface: "utun5", Servers: []string{"10.1.0.1"}},
	}
	if got := dnsFW(h).dnsAllow; !slices.EqualFunc(got, want, func(a, b firewall.DNSAllow) bool {
		return a.Interface == b.Interface && slices.Equal(a.Servers, b.Servers)
	}) {
		t.Fatalf("allow = %+v, want %+v", got, want)
	}
}

// Disconnecting one tunnel must drop its interface from the rules instead
// of leaving them pointed at a dead interface. Exercised through the
// rule-driven disconnect, which (unlike handleDisconnect) carries on past
// the test manager's "not connected" for a tunnel it never really had.
func TestDisconnect_RebuildsDNSProtectionForRemainingTunnels(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"alpha", "utun4", []string{"10.0.0.1"}}, tn{"bravo", "utun5", []string{"10.1.0.1"}})
	_ = h.reapplyDNSProtection()

	// bravo goes down.
	stubConnected(t, h, tn{"alpha", "utun4", []string{"10.0.0.1"}})
	h.disconnectAutoManaged("bravo")

	got := dnsFW(h).dnsAllow
	if len(got) != 1 || got[0].Interface != "utun4" {
		t.Fatalf("allow after disconnect = %+v, want only utun4", got)
	}
}

type disconnectFirewall struct {
	*pendingTestFirewall
	removed []string
}

func (f *disconnectFirewall) RemoveKillSwitchTunnel(iface string) error {
	f.removed = append(f.removed, iface)
	return nil
}

func TestDisconnectErrorStillReconcilesDNSAndOnlyRemovesDeadPermits(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"alpha", "utun4", []string{"10.0.0.1"}}, tn{"bravo", "utun5", []string{"10.1.0.1"}})
	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	fw := &disconnectFirewall{pendingTestFirewall: dnsFW(h)}
	fw.killSwitch = true
	h.firewall = fw
	// The manager has already lost alpha, so named teardown returns an
	// error. Its old permit snapshot still needs cleaning; bravo survives.
	delete(h.activeCfgs, "alpha")
	firstSnapshot := true
	tunnelStatuses = func(*Helper) []*tunnel.ConnectionStatus {
		live := []*tunnel.ConnectionStatus{{TunnelName: "bravo", InterfaceName: "utun5", State: domain.StateConnected}}
		if firstSnapshot {
			firstSnapshot = false
			return append(live, &tunnel.ConnectionStatus{TunnelName: "alpha", InterfaceName: "utun4", State: domain.StateConnected})
		}
		return live
	}
	if _, err := h.handleDisconnect(json.RawMessage(`{"tunnel_name":"alpha"}`)); err == nil {
		t.Fatal("original disconnect error was swallowed")
	}
	if !slices.Equal(fw.removed, []string{"utun4"}) {
		t.Fatalf("removed permits = %v, want only the dead interface", fw.removed)
	}
	if len(fw.dnsAllow) != 1 || fw.dnsAllow[0].Interface != "utun5" {
		t.Fatalf("DNS after failed teardown = %+v", fw.dnsAllow)
	}
}

func TestPartialDisconnectFirewallReconcilePreservesSurvivor(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"bravo", "utun5", []string{"10.1.0.1"}})
	fw := &disconnectFirewall{pendingTestFirewall: dnsFW(h)}
	fw.killSwitch = true
	h.firewall = fw
	h.reconcileDisconnectFirewall([]string{"utun4", "utun5"})
	if !slices.Equal(fw.removed, []string{"utun4"}) || len(fw.dnsAllow) != 1 || fw.dnsAllow[0].Interface != "utun5" {
		t.Fatalf("partial teardown lost survivor: removed=%v DNS=%+v", fw.removed, fw.dnsAllow)
	}
}

// The GUI/CLI used to send one tunnel's DNS list; the helper now derives the
// list itself and ignores the request's.
func TestHandleSetDNSProtection_IgnoresRequestServers(t *testing.T) {
	h := newPendingTestHelper(t)
	stubConnected(t, h, tn{"alpha", "utun4", []string{"10.0.0.1"}})

	params, _ := json.Marshal(ipc.DNSProtectionRequest{Enabled: true, DNSServers: []string{"9.9.9.9"}})
	if _, err := h.handleSetDNSProtection(params); err != nil {
		t.Fatal(err)
	}
	got := dnsFW(h).dnsAllow
	if len(got) != 1 || !slices.Equal(got[0].Servers, []string{"10.0.0.1"}) {
		t.Fatalf("allow = %+v, want the tunnel's own servers", got)
	}
	if !h.dnsProtectionWanted || !loadDesiredIntent(h.dataDir).DNSProtection {
		t.Fatal("setting should be recorded and persisted")
	}

	params, _ = json.Marshal(ipc.DNSProtectionRequest{Enabled: false})
	if _, err := h.handleSetDNSProtection(params); err != nil {
		t.Fatal(err)
	}
	if dnsFW(h).IsDNSProtectionEnabled() {
		t.Fatal("turning the setting off must remove the rules")
	}
}

// Turned on with nothing connected: recorded, and the first connect
// installs the rules.
func TestDNSProtection_OnWithoutTunnelAppliesOnConnect(t *testing.T) {
	h := newPendingTestHelper(t)
	stubConnected(t, h)
	params, _ := json.Marshal(ipc.DNSProtectionRequest{Enabled: true})
	if _, err := h.handleSetDNSProtection(params); err != nil {
		t.Fatal(err)
	}
	if dnsFW(h).IsDNSProtectionEnabled() {
		t.Fatal("no tunnel up: no rules yet")
	}

	stubConnected(t, h, tn{"alpha", "utun4", []string{"10.0.0.1"}})
	h.applyPostConnectFirewall(h.activeCfgs["alpha"])
	if got := dnsFW(h).dnsAllow; len(got) != 1 || got[0].Interface != "utun4" {
		t.Fatalf("allow after connect = %+v", got)
	}
}

// Resume after a reconnect rebuilds the same rules every time; the old code
// paired the first interface with servers from a random map entry.
func TestResumeFirewall_RebuildsDNSForAllTunnelsDeterministically(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"alpha", "utun4", []string{"10.0.0.1"}}, tn{"bravo", "utun5", []string{"10.1.0.1"}})
	for i := 0; i < 50; i++ {
		if err := h.suspendFirewall(); err != nil {
			t.Fatal(err)
		}
		if err := h.resumeFirewall(); err != nil {
			t.Fatal(err)
		}
		got := dnsFW(h).dnsAllow
		if len(got) != 2 || got[0].Interface != "utun4" || got[0].Servers[0] != "10.0.0.1" ||
			got[1].Interface != "utun5" || got[1].Servers[0] != "10.1.0.1" {
			t.Fatalf("round %d: allow = %+v", i, got)
		}
	}
}

// No tunnel with DNS servers left: the rules go away rather than block
// every resolver; the setting stays on for the next connect.
func TestReapplyDNSProtection_NoTunnelsRemovesRules(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"alpha", "utun4", []string{"10.0.0.1"}})
	_ = h.reapplyDNSProtection()
	stubConnected(t, h)
	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	if dnsFW(h).IsDNSProtectionEnabled() {
		t.Fatal("rules should be removed with no tunnel up")
	}
	if !h.dnsProtectionWanted {
		t.Fatal("the setting must survive")
	}
}

// Windows full tunnel: DNS protection comes on by itself; an explicit "off"
// holds (and the UI's "off" is true) until the next full-tunnel connect.
func TestDNSProtection_WindowsFullTunnelAutoAndExplicitOff(t *testing.T) {
	prev := fullTunnelForcesDNSProtection
	fullTunnelForcesDNSProtection = true
	t.Cleanup(func() { fullTunnelForcesDNSProtection = prev })

	h := newPendingTestHelper(t)
	stubConnected(t, h, tn{"full", "wg0", []string{"10.0.0.1"}})
	full := h.activeCfgs["full"]
	full.Peers = []domain.PeerConfig{{AllowedIPs: []string{"0.0.0.0/0"}}}
	if !full.IsFullTunnel() {
		t.Fatal("test config should be a full tunnel")
	}

	h.applyPostConnectFirewall(full)
	if !dnsFW(h).IsDNSProtectionEnabled() {
		t.Fatal("full tunnel should turn DNS protection on automatically")
	}

	params, _ := json.Marshal(ipc.DNSProtectionRequest{Enabled: false})
	if _, err := h.handleSetDNSProtection(params); err != nil {
		t.Fatal(err)
	}
	if dnsFW(h).IsDNSProtectionEnabled() {
		t.Fatal("explicit off must take effect while the full tunnel stays up")
	}
	_ = h.reapplyDNSProtection() // e.g. a reconnect
	if dnsFW(h).IsDNSProtectionEnabled() {
		t.Fatal("explicit off must hold across a reapply")
	}

	h.applyPostConnectFirewall(full) // next full-tunnel connect
	if !dnsFW(h).IsDNSProtectionEnabled() {
		t.Fatal("next full-tunnel connect turns it back on, as before")
	}
}
