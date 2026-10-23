package helper

import (
	"encoding/json"
	"errors"
	"github.com/korjwl1/wireguide/internal/firewall"
	"testing"
)

type dnsIntentFault struct {
	*pendingTestFirewall
	fail bool
}

func (f *dnsIntentFault) EnableDNSProtection(a []firewall.DNSAllow) error {
	if f.fail {
		return errors.New("temporary DNS apply error")
	}
	return f.pendingTestFirewall.EnableDNSProtection(a)
}
func TestDNSApplyFailurePreservesRequestedIntent(t *testing.T) {
	h := newPendingTestHelper(t)
	stubConnected(t, h, tn{"alpha", "utun4", []string{"10.0.0.1"}})
	f := &dnsIntentFault{pendingTestFirewall: dnsFW(h), fail: true}
	h.firewall = f
	if _, err := h.handleSetDNSProtection(json.RawMessage(`{"enabled":true}`)); err == nil {
		t.Fatal("missing injected failure")
	}
	if !h.dnsProtectionWanted || !loadDesiredIntent(h.dataDir).DNSProtection {
		t.Fatal("failed DNS apply lost requested protection")
	}
	f.fail = false
	if err := h.reconcileDNSProtection(false, h.dnsRetryAt); err != nil {
		t.Fatal(err)
	}
	if !f.IsDNSProtectionEnabled() {
		t.Fatal("periodic retry reverted to old setting")
	}
}
