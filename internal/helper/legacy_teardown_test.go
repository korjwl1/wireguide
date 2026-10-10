package helper

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/tunnel"
	"github.com/korjwl1/wireguide/internal/wifi"
)

// Rule-governed and latched tunnels survive the legacy teardown; plain ones
// are torn down so reconnectFn("") can rebuild them on the new network.
func TestLegacyTeardownLeavesAutomationAndLatchedTunnels(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, _ := newAutomationHelper(t, "x")
	writeAutomation(t, h, map[string][]wifi.Rule{
		"auto":    {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "x"}, Do: wifi.ActionConnect}},
		"latched": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "other"}, Do: wifi.ActionConnect}},
	})
	h.manualOverride["latched"] = manualLatch{identity: "ssid:x"}

	var down []string
	err := h.legacyTeardownWith([]string{"auto", "latched", "plain"}, func(n string) error {
		down = append(down, n)
		return nil
	})
	if err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if len(down) != 1 || down[0] != "plain" {
		t.Fatalf("only the plain tunnel may be disconnected, got %v", down)
	}

	// Every connected tunnel owned: nothing torn down, clean success.
	down = nil
	if err := h.legacyTeardownWith([]string{"auto", "latched"}, func(n string) error {
		down = append(down, n)
		return nil
	}); err != nil || len(down) != 0 {
		t.Fatalf("all-owned case: err=%v down=%v", err, down)
	}

	// ErrNotConnected is a no-op success; other errors propagate.
	if err := h.legacyTeardownWith([]string{"plain"}, func(string) error {
		return &tunnel.TunnelError{Kind: tunnel.ErrNotConnected, Message: "gone"}
	}); err != nil {
		t.Fatalf("ErrNotConnected must be tolerated: %v", err)
	}
	boom := errors.New("boom")
	if err := h.legacyTeardownWith([]string{"plain"}, func(string) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("want wrapped boom, got %v", err)
	}
}

// With every cached tunnel connected and rule-owned, the legacy reconnect
// ends cleanly (no error, so no backoff loop) and still re-evaluates.
func TestLegacyReconnectAllRuleTunnelsConnectedEndsCleanly(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, _ := newAutomationHelper(t, "x")
	writeAutomation(t, h, map[string][]wifi.Rule{
		"auto": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "x"}, Do: wifi.ActionConnect}},
	})
	h.activeCfgs["auto"] = cfgNamed("auto", "10.0.0.0/24")
	// "auto" is not connected in the (engine-less) manager, so it is deferred
	// to automation: success, no error.
	logs := captureLogs(t)
	if err := h.reconnectFn(t.Context(), ""); err != nil {
		t.Fatalf("want clean end, got %v", err)
	}
	// The async re-evaluation must still fire; wait for it so it does not
	// outlive the test's stubs.
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(logs.String(), "tunnel store unavailable") {
		if time.Now().After(deadline) {
			t.Fatalf("expected an async reevaluateAutomation(\"reconnect\"):\n%s", logs)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A report whose gateway MAC was unknown gets stamped lazily, so a later
// gateway change invalidates the SSID.
func TestSSIDStampLazyThenGatewayChangeInvalidates(t *testing.T) {
	p := wifiProbe()
	p.GatewayMAC = ""
	stubNetwork(t, p)
	h, _ := newAutomationHelper(t, "Home")
	h.wifiMu.Lock()
	h.ssidFromGUI = true
	h.wifiMu.Unlock()

	if st := h.currentNetworkState(); st.ctx.SSID != "Home" {
		t.Fatalf("SSID must be trusted with no gateway known: %+v", st.ctx)
	}
	if h.ssidStampGW != "" {
		t.Fatalf("no stamp expected yet, got %q", h.ssidStampGW)
	}

	p.GatewayMAC = "aa:aa:aa:aa:aa:aa"
	if st := h.currentNetworkState(); st.ctx.SSID != "Home" {
		t.Fatalf("SSID still valid on the stamping call: %+v", st.ctx)
	}
	h.wifiMu.Lock()
	stamp := h.ssidStampGW
	h.wifiMu.Unlock()
	if stamp != "aa:aa:aa:aa:aa:aa" {
		t.Fatalf("lazy stamp not recorded: %q", stamp)
	}

	p.GatewayMAC = "bb:bb:bb:bb:bb:bb"
	if st := h.currentNetworkState(); st.ctx.SSID != "" {
		t.Fatalf("gateway change must invalidate the SSID: %+v", st.ctx)
	}
}

// A helper-read SSID (Linux/Windows) is always fresh: a gateway change must
// never invalidate it, and no stamp is recorded.
func TestHelperReadSSIDNotInvalidatedByGatewayChange(t *testing.T) {
	p := wifiProbe()
	p.GatewayMAC = "aa:aa:aa:aa:aa:aa"
	stubNetwork(t, p)
	h, _ := newAutomationHelper(t, "Home")

	if st := h.currentNetworkState(); st.ctx.SSID != "Home" {
		t.Fatalf("SSID must be trusted: %+v", st.ctx)
	}
	p.GatewayMAC = "bb:bb:bb:bb:bb:bb"
	h.wifiMon.ReportExternalSSID("Office")
	if st := h.currentNetworkState(); st.ctx.SSID != "Office" {
		t.Fatalf("fresh helper-read SSID must survive a gateway change: %+v", st.ctx)
	}
	h.wifiMu.Lock()
	stamp := h.ssidStampGW
	h.wifiMu.Unlock()
	if stamp != "" {
		t.Fatalf("no stamp expected for helper-read SSIDs, got %q", stamp)
	}
}

// Every cached tunnel is connected and rule-owned: the legacy reconnect ends
// cleanly and still triggers the async re-evaluation.
func TestLegacyReconnectConnectedRuleTunnelStillReevaluates(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, _ := newAutomationHelper(t, "x")
	writeAutomation(t, h, map[string][]wifi.Rule{
		"auto": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "x"}, Do: wifi.ActionConnect}},
	})
	h.activeCfgs["auto"] = cfgNamed("auto", "10.0.0.0/24")
	h.connectedFn = func() []string { return []string{"auto"} }
	logs := captureLogs(t)
	if err := h.reconnectFn(t.Context(), ""); err != nil {
		t.Fatalf("want clean end, got %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(logs.String(), "tunnel store unavailable") {
		if time.Now().After(deadline) {
			t.Fatalf("expected an async reevaluateAutomation(\"reconnect\"):\n%s", logs)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// While a GUI is attached its reported SSID is authoritative: a gateway
// change without an SSID change (iPhone USB tethering ranked above Wi-Fi,
// Wi-Fi still associated) must not blank it.
func TestSSIDStampIgnoredWhileGUIAttached(t *testing.T) {
	p := wifiProbe()
	p.GatewayMAC = "aa:aa:aa:aa:aa:aa"
	stubNetwork(t, p)
	h, _ := newAutomationHelper(t, "HomeWiFi")
	attached := true
	h.guiAttachedFn = func() bool { return attached }
	h.wifiMu.Lock()
	h.ssidFromGUI = true
	h.ssidStampGW = "aa:aa:aa:aa:aa:aa"
	h.wifiMu.Unlock()

	p.GatewayMAC = "bb:bb:bb:bb:bb:bb"
	p.Iface = "en8"
	p.PrimaryIsWiFi = false
	if st := h.currentNetworkState(); st.ctx.SSID != "HomeWiFi" {
		t.Fatalf("attached GUI's SSID must survive a gateway change: %+v", st.ctx)
	}

	// Once the GUI is gone the stamp guard applies again.
	attached = false
	if st := h.currentNetworkState(); st.ctx.SSID != "" {
		t.Fatalf("without a GUI a gateway change must invalidate the SSID: %+v", st.ctx)
	}
}
