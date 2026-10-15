package helper

import (
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/wifi"
)

// Q3: a tunnel that a wake/health retry has already torn down (manager
// reports it inactive, activeCfgs still caches it) gets a rule "disconnect".
// The rule path only withdraws pendingDesired and cancels the per-name retry;
// activeCfgs keeps it, so the legacy all-tunnels reconnect brings it back.
func TestRuleDisconnectWithdrawsCachedTransport(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, clk := newAutomationHelper(t, "HomeWiFi")
	h.done = make(chan struct{})
	clk.Advance(time.Minute)
	writeAutomation(t, h, map[string][]wifi.Rule{
		"Site": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "HomeWiFi"}, Do: wifi.ActionDisconnect}},
	})
	cfg := &domain.WireGuardConfig{Name: "Site"}
	h.mu.Lock()
	h.activeCfgs["Site"] = cfg // torn down by the monitor, retry in backoff
	h.mu.Unlock()

	h.reevaluateAutomation("ssid-change")

	if h.stillCached("Site") {
		t.Fatal("rule Off retained cached transport for wake reconnect")
	}
}
