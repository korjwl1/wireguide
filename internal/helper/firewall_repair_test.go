package helper

import (
	"errors"
	"testing"
	"time"
)

type repairingFirewall struct {
	*pendingTestFirewall
	calls int
	err   error
}

func (f *repairingFirewall) RepairEnforcement() (bool, error) {
	f.calls++
	return f.err == nil, f.err
}

// Review H-1: enforcement lost outside WireGuide (external `pfctl -d`) is
// invisible to the model comparison, so the periodic pass must ask the
// backend to repair it, and keep asking after a failure.
func TestPeriodicPassRepairsLostFirewallEnforcement(t *testing.T) {
	h := newPendingTestHelper(t)
	fw := &repairingFirewall{pendingTestFirewall: dnsFW(h), err: errors.New("pfctl -E failed")}
	h.firewall = fw
	now := time.Now()
	h.reconcileFirewallTick(now)
	fw.err = nil
	h.reconcileFirewallTick(now.Add(time.Second))
	if fw.calls != 2 {
		t.Fatalf("repair calls = %d, want a retry after failure", fw.calls)
	}
}

func TestRepairSkippedWhileReconnectSuspendsFirewall(t *testing.T) {
	h := newPendingTestHelper(t)
	fw := &repairingFirewall{pendingTestFirewall: dnsFW(h)}
	h.firewall = fw
	h.fwSuspendDepth = 1
	h.repairFirewallEnforcement(time.Now())
	if fw.calls != 0 {
		t.Fatal("repair re-enabled rules a reconnect deliberately suspended")
	}
}

func TestRepairIgnoresBackendsWithoutRepairer(t *testing.T) {
	h := newPendingTestHelper(t)
	h.repairFirewallEnforcement(time.Now()) // pendingTestFirewall has no repairer: must not panic
}

func TestFirewallRepairBackoffIsBoundedAndResetsOnSuccess(t *testing.T) {
	h := newPendingTestHelper(t)
	f := &repairingFirewall{pendingTestFirewall: dnsFW(h), err: errors.New("bad pf.conf")}
	h.firewall = f
	now := time.Now()
	for attempt := 0; attempt < 8; attempt++ {
		h.repairFirewallEnforcement(now)
		if f.calls != attempt+1 || h.fwRepairRetryDelay > 30*time.Second {
			t.Fatal("repair backoff did not advance within its bound")
		}
		h.repairFirewallEnforcement(now.Add(time.Millisecond))
		if f.calls != attempt+1 {
			t.Fatal("repair ignored its retry deadline")
		}
		now = h.fwRepairRetryAt
	}
	f.err = nil
	h.repairFirewallEnforcement(now)
	if !h.fwRepairRetryAt.IsZero() || h.fwRepairRetryDelay != 0 {
		t.Fatal("successful repair retained stale backoff")
	}
}

// Backend contract after review M-10: a failed removal leaves the backend
// reporting DNS protection enabled. The helper must retry the removal on a
// later pass instead of recording the failed attempt as the applied state.
type failingDNSRemovalFirewall struct {
	*pendingTestFirewall
	failures, disables int
}

func (f *failingDNSRemovalFirewall) DisableDNSProtection() error {
	f.disables++
	if f.failures > 0 {
		f.failures--
		return errors.New("FwpmTransactionCommit0(DNS rm): 0x80320001")
	}
	return f.pendingTestFirewall.DisableDNSProtection()
}

func TestFailedDNSRemovalIsRetriedUntilBackendReportsRemoved(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"alpha", "utun4", []string{"10.0.0.1"}})
	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	fw := &failingDNSRemovalFirewall{pendingTestFirewall: dnsFW(h), failures: 1}
	h.firewall = fw
	stubConnected(t, h) // the last protected tunnel went away
	now := time.Now()
	if err := h.reconcileDNSProtection(false, now); err == nil {
		t.Fatal("removal failure hidden")
	}
	if err := h.reconcileDNSProtection(false, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if fw.disables != 2 || fw.IsDNSProtectionEnabled() {
		t.Fatalf("disables=%d enabled=%v; a failed removal was not retried", fw.disables, fw.IsDNSProtectionEnabled())
	}
}
