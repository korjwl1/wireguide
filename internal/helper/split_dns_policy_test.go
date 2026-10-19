package helper

import (
	"testing"
)

func TestSplitOnlyDNSProtectionPreservesSystemResolvers(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"corp", "utun4", []string{"10.0.0.53", "~corp.example"}})
	if h.dnsProtectionNeeded() {
		t.Fatal("split-only DNS must not globally block system resolvers")
	}
	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	if dnsFW(h).IsDNSProtectionEnabled() {
		t.Fatal("split-only tunnel installed a global DNS block")
	}
}

func TestMixedDNSProtectionAllowsSplitPublicResolver(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"global", "utun4", []string{"10.0.0.53"}}, tn{"split", "utun5", []string{"1.1.1.1", "~corp.example"}})
	// The split resolver uses the physical route, not the synthetic /32
	// supplied by the common fixture.
	h.activeCfgs["split"].Peers = nil
	if err := h.reapplyDNSProtection(); err != nil {
		t.Fatal(err)
	}
	for _, p := range dnsFW(h).dnsAllow {
		for _, s := range p.Servers {
			if s == "1.1.1.1" && p.Interface == "" {
				return
			}
		}
	}
	t.Fatal("mixed-mode policy blocked the split tunnel's physical resolver")
}
