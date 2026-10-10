package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/reconnect"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/tunnel"
	"github.com/korjwl1/wireguide/internal/wifi"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// stubNetwork installs a probe result and restores the seams afterwards.
func stubNetwork(t *testing.T, p *netProbeResult) {
	t.Helper()
	origProbe, origRoute, origOverlap := probeNetwork, defaultRouteProbe, localOverlapProbe
	t.Cleanup(func() { probeNetwork, defaultRouteProbe, localOverlapProbe = origProbe, origRoute, origOverlap })
	probeNetwork = func() netProbeResult { return *p }
	defaultRouteProbe = func() bool { return true }
	localOverlapProbe = func([]string) (string, net.IP, bool) { return "", nil, false }
}

func wifiProbe() *netProbeResult {
	return &netProbeResult{
		Gateway: "192.168.50.1", Iface: "en0", GatewayMAC: "b0:38:6c:54:8b:ab",
		Subnets: []string{"192.168.50.0/24"}, PrimaryIsWiFi: true,
	}
}

func newAutomationHelper(t *testing.T, ssid string) (*Helper, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Unix(10_000, 0)}
	h := newWiringHelper(t, &fakeFW{})
	h.settle = wifi.NewSettleTracker(clk.Now)
	h.manualOverride = map[string]manualLatch{}
	h.autoConnectedBy = map[string]string{}
	h.wifiMon = wifi.NewMonitor(nil)
	h.wifiMon.ReportExternalSSID(ssid)
	h.userAppSupport = t.TempDir()
	return h, clk
}

func TestNetworkContextFields(t *testing.T) {
	p := wifiProbe()
	stubNetwork(t, p)
	h, clk := newAutomationHelper(t, "CafeWiFi")

	st := h.currentNetworkState()
	if st.ctx.Settled || st.settleRemaining != wifi.NegationSettleWindow {
		t.Fatalf("fresh context must be unsettled: %+v rem=%v", st.ctx, st.settleRemaining)
	}
	if st.ctx.PrimaryIface != "en0" || !st.ctx.PrimaryIsWiFi || !st.ctx.Online {
		t.Fatalf("context fields: %+v", st.ctx)
	}
	if st.identity != "ssid:CafeWiFi" {
		t.Fatalf("identity %q", st.identity)
	}
	clk.Advance(wifi.NegationSettleWindow)
	if st := h.currentNetworkState(); !st.ctx.Settled {
		t.Fatal("must settle after the window")
	}

	// No SSID, Ethernet primary: identity falls back to the network triple.
	h.wifiMon.ReportExternalSSID("")
	p.Iface, p.PrimaryIsWiFi = "en5", false
	st = h.currentNetworkState()
	if st.identity != "net:en5|b0:38:6c:54:8b:ab|192.168.50.0/24" {
		t.Fatalf("identity %q", st.identity)
	}
	// Offline.
	p.Gateway, p.Iface = "", ""
	if st := h.currentNetworkState(); st.ctx.Online {
		t.Fatal("no default route must be offline")
	}
}

func TestManualLatchHoldsThroughBlipClearsOnSettledChange(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, clk := newAutomationHelper(t, "HomeWiFi")
	clk.Advance(time.Minute)

	h.recordManualOverride("Site", true)
	if l, ok := h.manualLatchFor("Site"); !ok || !l.disconnected || l.identity != "ssid:HomeWiFi" {
		t.Fatalf("latch %+v %v", l, ok)
	}

	// Roam blip: SSID goes blank, network is NOT settled -> latch stays.
	h.wifiMon.ReportExternalSSID("")
	st := h.currentNetworkState()
	if st.ctx.Settled {
		t.Fatal("blip must be unsettled")
	}
	h.pruneManualOverrides(st)
	if _, ok := h.manualLatchFor("Site"); !ok {
		t.Fatal("blip cleared the latch")
	}

	// Back on the same network and settled -> same identity, latch stays.
	h.wifiMon.ReportExternalSSID("HomeWiFi")
	h.currentNetworkState()
	clk.Advance(wifi.NegationSettleWindow)
	st = h.currentNetworkState()
	if !st.ctx.Settled {
		t.Fatal("expected settled")
	}
	h.pruneManualOverrides(st)
	if _, ok := h.manualLatchFor("Site"); !ok {
		t.Fatal("same settled identity must keep the latch")
	}

	// Settled on a different network -> cleared.
	h.wifiMon.ReportExternalSSID("CafeWiFi")
	h.currentNetworkState()
	clk.Advance(wifi.NegationSettleWindow)
	st = h.currentNetworkState()
	h.pruneManualOverrides(st)
	if _, ok := h.manualLatchFor("Site"); ok {
		t.Fatal("settled network change must clear the latch")
	}
}

func TestPruneLatchesWithoutRules(t *testing.T) {
	h, _ := newAutomationHelper(t, "x")
	h.manualOverride["a"] = manualLatch{identity: "i"}
	h.manualOverride["b"] = manualLatch{identity: "i"}
	h.pruneLatchesWithoutRules(map[string][]wifi.Rule{"a": {{Do: wifi.ActionConnect}}})
	if _, ok := h.manualOverride["a"]; !ok {
		t.Error("a has rules, must stay")
	}
	if _, ok := h.manualOverride["b"]; ok {
		t.Error("b has no rules, must be dropped")
	}
}

func TestRenameMovesLatch(t *testing.T) {
	h, _ := newAutomationHelper(t, "x")
	dir := t.TempDir()
	h.userTunnelStore = storage.NewTunnelStore(dir)
	conf := "[Interface]\nPrivateKey = 4Lc3MwNRFEH1dkqmwLfXPJ1j0RVPtv5dQ3TlkBe1CVI=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = bRgKrDAsB1OBFKLrCiB0bIvGKsPMGDqGBUl2bG0AEgY=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 10.0.0.0/24\n"
	if err := os.WriteFile(filepath.Join(dir, "old.conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	h.manualOverride["old"] = manualLatch{identity: "ssid:x", disconnected: true}
	params, _ := json.Marshal(ipc.RenameRequest{OldName: "old", NewName: "new"})
	if _, err := h.handleRename(params); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.manualOverride["old"]; ok {
		t.Error("old latch must be gone")
	}
	if l, ok := h.manualOverride["new"]; !ok || !l.disconnected {
		t.Errorf("latch not moved: %+v %v", l, ok)
	}
}

// logBuf is a goroutine-safe log sink.
type logBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *logBuf) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.String() }
func (b *logBuf) Reset()         { b.mu.Lock(); defer b.mu.Unlock(); b.buf.Reset() }

// captureLogs routes slog to a buffer for the test's duration.
func captureLogs(t *testing.T) *logBuf {
	t.Helper()
	buf := &logBuf{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

func writeAutomation(t *testing.T, h *Helper, rules map[string][]wifi.Rule) {
	t.Helper()
	s := storage.DefaultSettings()
	s.Automation = &wifi.Automation{PerTunnel: rules}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.userAppSupport, "config.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReevaluateRespectsLatchAndArmsSettleTimer(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, clk := newAutomationHelper(t, "CafeWiFi")
	h.done = make(chan struct{})
	t.Cleanup(h.stopSettleTimer)
	writeAutomation(t, h, map[string][]wifi.Rule{
		"Site": {
			{When: wifi.Condition{Type: wifi.CondSSID, SSID: "HomeWiFi"}, Do: wifi.ActionDisconnect},
			{When: wifi.Condition{Type: wifi.CondSSID, Negate: true, SSID: "HomeWiFi"}, Do: wifi.ActionConnect},
		},
	})

	// Unsettled: the negated rule holds -> no connect attempt, timer armed.
	logs := captureLogs(t)
	h.reevaluateAutomation("test")
	if strings.Contains(logs.String(), "tunnel store unavailable") {
		t.Fatalf("unsettled negated rule must not connect:\n%s", logs)
	}
	h.settleMu.Lock()
	armed := h.settleTimer != nil
	h.settleMu.Unlock()
	if !armed {
		t.Fatal("settle timer not armed")
	}

	// Settled: the rule connects (observed via the missing tunnel store).
	clk.Advance(wifi.NegationSettleWindow)
	logs.Reset()
	h.reevaluateAutomation("test")
	if !strings.Contains(logs.String(), "tunnel store unavailable") {
		t.Fatalf("settled negated rule should attempt a connect:\n%s", logs)
	}

	// Latched: automation must not touch it.
	h.manualOverride["Site"] = manualLatch{identity: "ssid:CafeWiFi", disconnected: true}
	logs.Reset()
	h.reevaluateAutomation("test")
	if strings.Contains(logs.String(), "tunnel store unavailable") {
		t.Fatalf("latched tunnel must not be connected:\n%s", logs)
	}
}

func TestAlreadyConnectedIsOK(t *testing.T) {
	if err := alreadyConnectedIsOK(&tunnel.TunnelError{Kind: tunnel.ErrAlreadyConnected, Message: "x"}); err != nil {
		t.Errorf("ErrAlreadyConnected must be success, got %v", err)
	}
	other := &tunnel.TunnelError{Kind: tunnel.ErrNetwork, Message: "x"}
	if err := alreadyConnectedIsOK(other); err != other {
		t.Errorf("other errors pass through, got %v", err)
	}
	if alreadyConnectedIsOK(nil) != nil {
		t.Error("nil stays nil")
	}
}

func cfgNamed(name string, allowed ...string) *domain.WireGuardConfig {
	return &domain.WireGuardConfig{Name: name, Peers: []domain.PeerConfig{{AllowedIPs: allowed}}}
}

func TestLegacyReconnectSkipsAutomationAndLatched(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, _ := newAutomationHelper(t, "x")
	writeAutomation(t, h, map[string][]wifi.Rule{
		"auto": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "x"}, Do: wifi.ActionConnect}},
		// (latches only survive for tunnels that still have rules)
		"off": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "other"}, Do: wifi.ActionConnect}},
	})
	// "auto" is rule-governed; "off" was disconnected by the user. Neither
	// may be connected by the legacy path: any attempt would hit the real
	// manager (no engine) and fail loudly.
	h.activeCfgs["auto"] = cfgNamed("auto", "10.0.0.0/24")
	h.activeCfgs["off"] = cfgNamed("off", "10.1.0.0/24")
	h.manualOverride["off"] = manualLatch{identity: "ssid:x", disconnected: true}

	logs := captureLogs(t)
	err := h.reconnectFn(context.Background(), "")
	if err != nil {
		t.Fatalf("automation-deferred reconnect should succeed without connecting: %v", err)
	}
	// The deferred tunnel is handed to a (async) automation re-evaluation,
	// which here reaches the connect step for the matching "auto" rule.
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(logs.String(), "tunnel store unavailable") {
		if time.Now().After(deadline) {
			t.Fatalf("expected an async reevaluateAutomation(\"reconnect\"):\n%s", logs)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// With only the user-disconnected tunnel left, there is nothing to do.
	delete(h.activeCfgs, "auto")
	if err := h.reconnectFn(context.Background(), ""); err != reconnect.ErrNothingToReconnect {
		t.Fatalf("want ErrNothingToReconnect, got %v", err)
	}
	// No cached config at all.
	h.activeCfgs = map[string]*domain.WireGuardConfig{}
	if err := h.reconnectFn(context.Background(), ""); err != reconnect.ErrNothingToReconnect {
		t.Fatalf("want ErrNothingToReconnect, got %v", err)
	}
}

func TestLegacyReconnectSkipsLANOverlap(t *testing.T) {
	stubNetwork(t, wifiProbe())
	localOverlapProbe = func(cidrs []string) (string, net.IP, bool) {
		for _, c := range cidrs {
			if c == "192.168.50.0/24" {
				return c, net.ParseIP("192.168.50.65"), true
			}
		}
		return "", nil, false
	}
	h, _ := newAutomationHelper(t, "x")
	h.activeCfgs["lan"] = cfgNamed("lan", "192.168.50.0/24")
	logs := captureLogs(t)
	if err := h.reconnectFn(context.Background(), ""); err != reconnect.ErrNothingToReconnect {
		t.Fatalf("want ErrNothingToReconnect, got %v", err)
	}
	if !strings.Contains(logs.String(), "overlap the local network") {
		t.Errorf("expected an Info log about the overlap:\n%s", logs)
	}
}

func TestAutomationConnectSkipsLANOverlap(t *testing.T) {
	stubNetwork(t, wifiProbe())
	localOverlapProbe = func([]string) (string, net.IP, bool) {
		return "192.168.50.0/24", net.ParseIP("192.168.50.65"), true
	}
	h, _ := newAutomationHelper(t, "x")
	dir := t.TempDir()
	h.userTunnelStore = storage.NewTunnelStore(dir)
	conf := "[Interface]\nPrivateKey = 4Lc3MwNRFEH1dkqmwLfXPJ1j0RVPtv5dQ3TlkBe1CVI=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = bRgKrDAsB1OBFKLrCiB0bIvGKsPMGDqGBUl2bG0AEgY=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 192.168.50.0/24\n"
	if err := os.WriteFile(filepath.Join(dir, "lan.conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	logs := captureLogs(t)
	h.automationConnect("lan", "test", "x")
	if !strings.Contains(logs.String(), "overlap the local network") || strings.Contains(logs.String(), "rule connect") {
		t.Errorf("automation must skip the overlapping tunnel:\n%s", logs)
	}
}

func TestWaitForDefaultRoute(t *testing.T) {
	orig := defaultRouteProbe
	defer func() { defaultRouteProbe = orig }()
	calls := 0
	defaultRouteProbe = func() bool { calls++; return calls >= 2 }
	if err := waitForDefaultRoute(context.Background(), 5*time.Second); err != nil || calls < 2 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
	defaultRouteProbe = func() bool { return false }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForDefaultRoute(ctx, 5*time.Second); err == nil {
		t.Fatal("cancelled ctx must abort the wait")
	}
}

// A rule tunnel whose rules don't decide the current network (unmanaged) is
// not deferred to automation: nothing would restore it after the monitor's
// teardown, so the legacy path must attempt the connect itself.
func TestLegacyReconnectRestoresUnmanagedRuleTunnel(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, _ := newAutomationHelper(t, "cafe")
	writeAutomation(t, h, map[string][]wifi.Rule{
		"Site": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "CafeWiFi"}, Do: wifi.ActionConnect}},
	})
	h.activeCfgs["Site"] = cfgNamed("Site", "10.0.0.0/24")

	logs := captureLogs(t)
	err := h.reconnectFn(context.Background(), "")
	if strings.Contains(logs.String(), "leaving tunnel to automation") {
		t.Fatalf("unmanaged rule tunnel must not be deferred:\n%s", logs)
	}
	// The attempt hits the engine-less test manager and fails, which proves
	// a connect was tried (deferral would return nil, a skip
	// ErrNothingToReconnect).
	if err == nil || err == reconnect.ErrNothingToReconnect {
		t.Fatalf("expected a failed connect attempt, got %v", err)
	}
}

func TestSettleTimerArmedForLatchWithPositiveOnlyRules(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, _ := newAutomationHelper(t, "Home")
	h.done = make(chan struct{})
	t.Cleanup(h.stopSettleTimer)
	writeAutomation(t, h, map[string][]wifi.Rule{
		"T": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "Cafe"}, Do: wifi.ActionConnect}},
	})
	h.manualOverride["T"] = manualLatch{identity: "ssid:Cafe", disconnected: true}

	h.reevaluateAutomation("test")
	h.settleMu.Lock()
	armed := h.settleTimer != nil
	h.settleMu.Unlock()
	if !armed {
		t.Fatal("settle timer must be armed while a latch is held on an unsettled network")
	}
}

func TestLatchSurvivesOfflineAndAdoptsKnownIdentity(t *testing.T) {
	p := wifiProbe()
	stubNetwork(t, p)
	h, clk := newAutomationHelper(t, "HomeWiFi")
	clk.Advance(time.Minute)
	h.recordManualOverride("Site", false)

	// Offline for longer than the settle window: latch must stay.
	p.Gateway, p.Iface = "", ""
	h.currentNetworkState()
	clk.Advance(wifi.NegationSettleWindow)
	st := h.currentNetworkState()
	if !st.ctx.Settled || st.ctx.Online {
		t.Fatalf("expected settled offline: %+v", st.ctx)
	}
	h.pruneManualOverrides(st)
	if _, ok := h.manualLatchFor("Site"); !ok {
		t.Fatal("offline period cleared the latch")
	}

	// Latch recorded with a blank SSID on Wi-Fi adopts the later known
	// identity instead of being cleared by it.
	p.Gateway, p.Iface = "192.168.50.1", "en0"
	h.wifiMon.ReportExternalSSID("")
	h.currentNetworkState()
	clk.Advance(wifi.NegationSettleWindow)
	h.currentNetworkState()
	h.recordManualOverride("T2", false)
	if l, _ := h.manualLatchFor("T2"); !l.unknown {
		t.Fatalf("latch recorded with blank SSID must be unknown: %+v", l)
	}
	h.wifiMon.ReportExternalSSID("HomeWiFi")
	h.currentNetworkState()
	clk.Advance(wifi.NegationSettleWindow)
	st = h.currentNetworkState()
	h.pruneManualOverrides(st)
	l, ok := h.manualLatchFor("T2")
	if !ok || l.unknown || l.identity != "ssid:HomeWiFi" {
		t.Fatalf("latch should adopt the known identity: %+v %v", l, ok)
	}
}

// startPendingRetry starts a monitor with a per-tunnel retry pending for name
// (its reconnect always fails, as after a failed reconnect).
func startPendingRetry(t *testing.T, name string) *reconnect.Monitor {
	t.Helper()
	queued := make(chan struct{}, 1)
	mon := reconnect.NewMonitor(&pingRetryManager{}, func(context.Context, string) error {
		return errors.New("endpoint lookup failed")
	}, func(st reconnect.State) {
		if st.Reconnecting {
			select {
			case queued <- struct{}{}:
			default:
			}
		}
	}, reconnect.Config{InitialDelay: time.Hour, MaxDelay: time.Hour})
	mon.Start()
	t.Cleanup(mon.Stop)
	mon.ReconnectTunnelIfIdle(name, nil)
	select {
	case <-queued:
	case <-time.After(2 * time.Second):
		t.Fatal("retry was not queued")
	}
	return mon
}

// A tunnel that a failed reconnect already took down can still have a
// health-check retry pending. When automation wants that tunnel down, the
// retry must be cancelled so it cannot bring the tunnel back.
func TestRuleDisconnectCancelsRetryForInactiveTunnel(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, _ := newAutomationHelper(t, "HomeWiFi")
	h.done = make(chan struct{})
	writeAutomation(t, h, map[string][]wifi.Rule{
		"home-vpn": {
			{When: wifi.Condition{Type: wifi.CondSSID, SSID: "HomeWiFi"}, Do: wifi.ActionDisconnect},
		},
	})
	h.monitor = startPendingRetry(t, "home-vpn")

	h.reevaluateAutomation("test")
	if h.monitor.GetState().Reconnecting {
		t.Fatal("rule disconnect left a reconnect retry pending for the tunnel")
	}
}
