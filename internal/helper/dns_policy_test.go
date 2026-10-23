package helper

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
)

func TestDNSPermitsFollowConnectedRoutes(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		ownerRoutes, otherRoutes []string
		table                    string
		want                     string
	}{
		{"public split resolver", []string{"10.0.0.0/24"}, nil, "", ""},
		{"own full tunnel", []string{"0.0.0.0/0"}, nil, "", "utun4"},
		{"other full tunnel", []string{"10.0.0.0/24"}, []string{"0.0.0.0/0"}, "", "utun5"},
		{"more specific other tunnel", []string{"0.0.0.0/0"}, []string{"1.1.1.0/24"}, "", "utun5"},
		{"table off", []string{"0.0.0.0/0"}, nil, "off", ""},
		{"split default pair", []string{"0.0.0.0/1", "128.0.0.0/1"}, nil, "", "utun4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newPendingTestHelper(t)
			stubConnected(t, h, tn{"alpha", "utun4", []string{"1.1.1.1", "corp.example"}}, tn{"bravo", "utun5", nil})
			h.activeCfgs["alpha"].Peers = []domain.PeerConfig{{AllowedIPs: tc.ownerRoutes}}
			h.activeCfgs["alpha"].Interface.Table = tc.table
			h.activeCfgs["bravo"].Peers = []domain.PeerConfig{{AllowedIPs: tc.otherRoutes}}
			want := []firewall.DNSAllow{{Interface: tc.want, Servers: []string{"1.1.1.1"}}}
			if got := h.dnsAllowList(); !reflect.DeepEqual(got, want) {
				t.Fatalf("permits = %+v, want %+v", got, want)
			}
		})
	}
}

type failingDNSFirewall struct {
	*pendingTestFirewall
	fail  bool
	calls int
}

func (f *failingDNSFirewall) EnableDNSProtection(allow []firewall.DNSAllow) error {
	f.calls++
	if f.fail {
		return errors.New("temporary firewall failure")
	}
	return f.pendingTestFirewall.EnableDNSProtection(allow)
}

func TestDNSReconciliationRetriesFailureAndSkipsHealthyRules(t *testing.T) {
	h := newPendingTestHelper(t)
	h.dnsProtectionWanted = true
	stubConnected(t, h, tn{"alpha", "utun4", []string{"10.0.0.1"}})
	fw := &failingDNSFirewall{pendingTestFirewall: dnsFW(h), fail: true}
	h.firewall = fw
	now := time.Now()
	if err := h.reconcileDNSProtection(false, now); err == nil {
		t.Fatal("failure hidden")
	}
	if err := h.reconcileDNSProtection(false, now.Add(time.Millisecond)); err != nil || fw.calls != 1 {
		t.Fatal("failed reconciliation ignored retry backoff")
	}
	fw.fail = false
	if err := h.reconcileDNSProtection(false, now.Add(2*time.Second)); err != nil || !fw.dns {
		t.Fatalf("retry: %v", err)
	}
	if err := h.reconcileDNSProtection(false, now.Add(10*time.Second)); err != nil || fw.calls != 2 {
		t.Fatal("healthy rules reloaded")
	}
	h.dnsSuspended = true
	h.dnsApplied = ""
	_ = h.reconcileDNSProtection(false, now.Add(20*time.Second))
	if fw.calls != 2 {
		t.Fatal("background reconcile undid reconnect suspension")
	}
}
