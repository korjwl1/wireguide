package domain

import (
	"reflect"
	"testing"
)

func TestParseDNSEntries(t *testing.T) {
	got := ParseDNSEntries([]string{" 1.1.1.1 ", "corp.lan", "~internal.example", "CORP.LAN", "2606:4700::1111", "1.1.1.1", "~", "~.", "~~x", "", "~Internal.Example"})
	want := DNSEntries{
		Servers: []string{"1.1.1.1", "2606:4700::1111"},
		Search:  []string{"corp.lan"},
		Match:   []string{"internal.example"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
}

func TestParseDNSEntriesEmpty(t *testing.T) {
	got := ParseDNSEntries(nil)
	if len(got.Servers)+len(got.Search)+len(got.Match) != 0 {
		t.Fatalf("expected empty, got %+v", got)
	}
}

func TestIsSplitDNS(t *testing.T) {
	if (InterfaceConfig{DNS: []string{"10.0.0.1", "corp.lan"}}).IsSplitDNS() {
		t.Fatal("search-only must not be split DNS")
	}
	if !(InterfaceConfig{DNS: []string{"10.0.0.1", "~corp.lan"}}).IsSplitDNS() {
		t.Fatal("match domain must be split DNS")
	}
}

func TestOwnsDefaultRoute(t *testing.T) {
	cases := []struct {
		name string
		ips  []string
		want bool
	}{
		{"v4 default", []string{"0.0.0.0/0"}, true},
		{"v6 default", []string{"::/0"}, true},
		{"v4 halves", []string{"0.0.0.0/1", "128.0.0.0/1"}, true},
		{"v6 halves", []string{"::/1", "8000::/1"}, true},
		{"only one half", []string{"0.0.0.0/1"}, false},
		{"mixed families halves no", []string{"0.0.0.0/1", "8000::/1"}, false},
		{"split", []string{"192.168.1.0/24"}, false},
		{"invalid", []string{"nonsense"}, false},
	}
	for _, c := range cases {
		cfg := &WireGuardConfig{Peers: []PeerConfig{{AllowedIPs: c.ips}}}
		if got := cfg.OwnsDefaultRoute(); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	// halves spread across two peers
	cfg := &WireGuardConfig{Peers: []PeerConfig{{AllowedIPs: []string{"0.0.0.0/1"}}, {AllowedIPs: []string{"128.0.0.0/1"}}}}
	if !cfg.OwnsDefaultRoute() {
		t.Error("halves across peers should own default route")
	}
}
