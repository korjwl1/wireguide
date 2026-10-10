//go:build linux

package firewall

import (
	"errors"
	"strings"
	"testing"
)

func TestRenderDNSTablePinnedAndUnpinned(t *testing.T) {
	got := renderDNSTable([]DNSPermit{
		{Interface: "wg0", Server: "10.0.0.1"},
		{Interface: "", Server: "1.1.1.1"},
		{Interface: "wg1", Server: "10.1.0.1"},
		{Interface: "wg0", Server: "10.0.0.1"}, // duplicate
	})
	for _, want := range []string{
		`ip daddr 10.0.0.1 tcp dport 53 oifname "wg0" accept`,
		`ip daddr 10.1.0.1 udp dport 53 oifname "wg1" accept`,
		"ip daddr 1.1.1.1 udp dport 53 accept",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "1.1.1.1 udp dport 53 oif") {
		t.Fatalf("unpinned permit must have no interface match:\n%s", got)
	}
	if strings.Count(got, "daddr 10.0.0.1 tcp") != 1 {
		t.Fatalf("duplicate permit rendered twice:\n%s", got)
	}
}

func TestRenderDNSTableEmptyOrInvalid(t *testing.T) {
	if renderDNSTable(nil) != "" {
		t.Fatal("empty set must render nothing")
	}
	if renderDNSTable([]DNSPermit{{Interface: "bad iface!", Server: "1.1.1.1"}, {Server: "nope"}}) != "" {
		t.Fatal("invalid permits must be skipped")
	}
}

func TestSetDNSPermitsNilPropagatesDeleteFailure(t *testing.T) {
	orig := nftDeleteDNSTable
	defer func() { nftDeleteDNSTable = orig }()
	calls := 0
	nftDeleteDNSTable = func() ([]byte, error) {
		calls++
		return []byte("netlink busy"), errors.New("exit status 1")
	}
	f := &LinuxFirewall{dnsProtectionEnabled: true}
	if err := f.SetDNSPermits(nil); err == nil {
		t.Fatal("failed delete must propagate")
	}
	if !f.dnsProtectionEnabled {
		t.Fatal("flag must stay set while the table may still exist")
	}
	if err := f.SetDNSPermits(nil); err == nil || calls != 2 {
		t.Fatalf("second reconcile must retry the delete, calls=%d err=%v", calls, err)
	}
	if err := f.DisableDNSProtection(); err == nil {
		t.Fatal("DisableDNSProtection must propagate")
	}
	nftDeleteDNSTable = func() ([]byte, error) {
		return []byte("Error: No such file or directory"), errors.New("exit status 1")
	}
	if err := f.SetDNSPermits(nil); err != nil || f.dnsProtectionEnabled {
		t.Fatalf("not-found is success: err=%v", err)
	}
}
