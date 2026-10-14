package helper

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/wifi"
)

var negatedRules = map[string][]wifi.Rule{
	"T": {{When: wifi.Condition{Type: wifi.CondSSID, Negate: true, SSID: "HomeWiFi"}, Do: wifi.ActionConnect}},
}

// bumpStat makes every tick see a changed config.json stat.
func bumpStat(h *Helper) {
	var n int64
	h.rulesStat = func(string) (int64, int64, error) { n++; return n, n, nil }
}

func TestRulesWatchTriggersOnlyOnAutomationChange(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, _ := newAutomationHelper(t, "CafeWiFi")
	var calls atomic.Int32
	var reason atomic.Value
	h.reevalTrigger = func(r string) { calls.Add(1); reason.Store(r) }
	bumpStat(h)

	// Baseline (no rules), as rulesWatchLoop records it.
	w := &rulesWatcher{}
	w.hash, _ = h.automationHash()

	h.rulesWatchTick(w) // stat changed, automation identical
	if calls.Load() != 0 {
		t.Fatalf("unchanged automation must not re-evaluate, got %d", calls.Load())
	}

	// Only another setting changes.
	s := storage.DefaultSettings()
	s.Theme = "dark"
	writeSettings(t, h, s)
	h.rulesWatchTick(w)
	if calls.Load() != 0 {
		t.Fatalf("theme-only change must not re-evaluate, got %d", calls.Load())
	}

	writeAutomation(t, h, negatedRules)
	h.rulesWatchTick(w)
	if calls.Load() != 1 || reason.Load() != "rules-changed" {
		t.Fatalf("rules change: calls=%d reason=%v", calls.Load(), reason.Load())
	}
	h.rulesWatchTick(w) // same rules again
	if calls.Load() != 1 {
		t.Fatalf("same rules must not re-trigger, got %d", calls.Load())
	}
}

func TestRulesWatchLoopBaselineDoesNotTrigger(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, _ := newAutomationHelper(t, "CafeWiFi")
	h.done = make(chan struct{})
	writeAutomation(t, h, negatedRules)
	var calls atomic.Int32
	h.reevalTrigger = func(string) { calls.Add(1) }
	h.rulesWatchInterval = 5 * time.Millisecond
	var mu sync.Mutex
	h.rulesStat = func(string) (int64, int64, error) { mu.Lock(); defer mu.Unlock(); return 1, 1, nil }
	finished := make(chan struct{})
	go func() { h.rulesWatchLoop(); close(finished) }()
	time.Sleep(60 * time.Millisecond)
	close(h.done)
	<-finished
	if calls.Load() != 0 {
		t.Fatalf("startup rules must not trigger, got %d", calls.Load())
	}
}

// End to end: a GUI-attached helper with no rules at startup; rules saved
// later must arm the settle timer via the watcher.
func TestRulesWatchArmsSettleTimerForNewRules(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, _ := newAutomationHelper(t, "CafeWiFi")
	h.done = make(chan struct{})
	t.Cleanup(h.stopSettleTimer)
	bumpStat(h)
	w := &rulesWatcher{}
	w.hash, _ = h.automationHash()

	h.reevaluateAutomation("startup")
	if h.settleTimerArmed() {
		t.Fatal("no rules: no settle timer expected")
	}
	writeAutomation(t, h, negatedRules)
	h.rulesWatchTick(w)
	if !h.settleTimerArmed() {
		t.Fatal("rules saved after startup must arm the settle timer")
	}
}

func TestPreviewDriftKicksOnceAndIsRateLimited(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, _ := newAutomationHelper(t, "CafeWiFi")
	h.done = make(chan struct{})
	writeAutomation(t, h, negatedRules)
	calls := make(chan string, 8)
	h.reevalTrigger = func(r string) { calls <- r }
	now := time.Unix(1_000, 0)
	h.previewDriftNow = func() time.Time { return now }

	if _, err := h.handleAutomationPreview(nil); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-calls:
		if r != "preview-drift" {
			t.Fatalf("reason %q", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stale tracker must trigger an evaluation")
	}
	// Within the rate limit: no second call.
	h.handleAutomationPreview(nil)
	select {
	case <-calls:
		t.Fatal("rate limit violated")
	case <-time.After(100 * time.Millisecond):
	}
	now = now.Add(previewDriftInterval + time.Second)
	h.handleAutomationPreview(nil)
	select {
	case <-calls:
	case <-time.After(2 * time.Second):
		t.Fatal("must trigger again after the interval")
	}
}

func TestPreviewDriftSkippedWithoutNegatedRulesOrWhenTimerArmed(t *testing.T) {
	stubNetwork(t, wifiProbe())
	h, _ := newAutomationHelper(t, "CafeWiFi")
	h.done = make(chan struct{})
	t.Cleanup(h.stopSettleTimer)
	var calls atomic.Int32
	h.reevalTrigger = func(string) { calls.Add(1) }
	writeAutomation(t, h, map[string][]wifi.Rule{
		"T": {{When: wifi.Condition{Type: wifi.CondSSID, SSID: "X"}, Do: wifi.ActionConnect}},
	})
	h.handleAutomationPreview(nil)
	writeAutomation(t, h, negatedRules)
	h.armSettleTimer(time.Hour)
	h.previewDriftLast = time.Time{}
	h.handleAutomationPreview(nil)
	time.Sleep(100 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatalf("no drift evaluation expected, got %d", calls.Load())
	}
}

func TestSubnetsOfAddrsAndPrimaryOnly(t *testing.T) {
	_, a, _ := net.ParseCIDR("192.168.50.0/24")
	got := subnetsOfAddrs([]net.Addr{
		&net.IPNet{IP: net.ParseIP("192.168.50.7"), Mask: a.Mask},
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("192.168.50.9"), Mask: a.Mask},
	})
	if len(got) != 1 || got[0] != "192.168.50.0/24" {
		t.Fatalf("subnets %v", got)
	}
}

func TestFingerprintIgnoresNonPrimarySubnets(t *testing.T) {
	orig := primarySubnets
	t.Cleanup(func() { primarySubnets = orig })
	var asked []string
	primarySubnets = func(iface string) []string { asked = append(asked, iface); return []string{"10.0.0.0/24"} }
	r := probeNetwork()
	if len(asked) != 1 || asked[0] != r.Iface {
		t.Fatalf("probe must ask for the primary iface only: asked=%v iface=%q", asked, r.Iface)
	}
	if len(r.Subnets) != 1 || r.Subnets[0] != "10.0.0.0/24" {
		t.Fatalf("subnets %v", r.Subnets)
	}
}

func writeSettings(t *testing.T, h *Helper, s *storage.Settings) {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.userAppSupport, "config.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}
