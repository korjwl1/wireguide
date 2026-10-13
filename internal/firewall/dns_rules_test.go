package firewall

import (
	"regexp"
	"strings"
	"testing"
)

var testIface = regexp.MustCompile(`^[a-z]+[0-9]+$`).MatchString

func TestNormalizeDNSAllow(t *testing.T) {
	got := normalizeDNSAllow([]DNSAllow{
		{Interface: "utun5", Servers: []string{"10.1.0.1", "corp.example", "10.1.0.1"}},
		{Interface: "utun4", Servers: []string{" 10.0.0.1 ", "fd00::53"}},
		{Interface: "bad iface", Servers: []string{"10.9.9.9"}},
		{Interface: "utun6", Servers: []string{"only.search.domain"}},
		{Interface: "", Servers: []string{"10.8.8.8"}},
	}, testIface)

	want := []DNSAllow{
		{Interface: "", Servers: []string{"10.8.8.8"}},
		{Interface: "utun4", Servers: []string{"10.0.0.1", "fd00::53"}},
		{Interface: "utun5", Servers: []string{"10.1.0.1"}},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].Interface != want[i].Interface || strings.Join(got[i].Servers, ",") != strings.Join(want[i].Servers, ",") {
			t.Fatalf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// A search domain next to the servers must not void protection (macOS used
// to reject the whole list).
func TestNormalizeDNSAllow_SearchDomainKeepsServers(t *testing.T) {
	got := normalizeDNSAllow([]DNSAllow{{Interface: "utun4", Servers: []string{"10.0.0.1", "corp.example"}}}, testIface)
	if len(got) != 1 || len(got[0].Servers) != 1 || got[0].Servers[0] != "10.0.0.1" {
		t.Fatalf("got %+v", got)
	}
}

func TestPfDNSRules(t *testing.T) {
	got := pfDNSRules([]DNSAllow{
		{Interface: "utun4", Servers: []string{"10.0.0.1"}},
		{Interface: "utun5", Servers: []string{"10.1.0.1", "fd00::53"}},
	})
	want := "pass out quick on lo0 proto {tcp, udp} to any port 53\n" +
		"pass out quick on utun4 proto {tcp, udp} to 10.0.0.1 port 53\n" +
		"pass out quick on utun5 proto {tcp, udp} to 10.1.0.1 port 53\n" +
		"pass out quick on utun5 proto {tcp, udp} to fd00::53 port 53\n" +
		"block drop out quick proto {tcp, udp} to any port 53\n"
	if got != want {
		t.Fatalf("pf rules:\n%s\nwant:\n%s", got, want)
	}
}

// Re-applying must replace the table: the batch deletes it before the
// definition, so allows never land behind an earlier enable's drops.
func TestNftDNSRules_ReplacesTableAtomically(t *testing.T) {
	got := nftDNSRules("wireguide", []DNSAllow{
		{Interface: "wg0", Servers: []string{"10.0.0.1"}},
		{Interface: "wg1", Servers: []string{"fd00::53"}},
	})
	add := strings.Index(got, "add table inet wireguide_dns\n")
	del := strings.Index(got, "delete table inet wireguide_dns\n")
	def := strings.Index(got, "table inet wireguide_dns {")
	if add != 0 || del < add || def < del {
		t.Fatalf("batch must be add, delete, then define:\n%s", got)
	}
	for _, line := range []string{
		"ip daddr 10.0.0.1 udp dport 53 oifname \"wg0\" accept",
		"ip daddr 10.0.0.1 tcp dport 53 oifname \"wg0\" accept",
		"ip6 daddr fd00::53 udp dport 53 oifname \"wg1\" accept",
	} {
		if !strings.Contains(got, line) {
			t.Fatalf("missing %q in:\n%s", line, got)
		}
	}
	if strings.Index(got, "oifname \"wg1\" accept") > strings.Index(got, "udp dport 53 drop") {
		t.Fatalf("allows must come before the drops:\n%s", got)
	}
}

func TestDNSRulesPermitPhysicalResolverByAddressOnly(t *testing.T) {
	allow := normalizeDNSAllow([]DNSAllow{{Servers: []string{"1.1.1.1"}}}, testIface)
	pf, nft := pfDNSRules(allow), nftDNSRules("wireguide", allow)
	if !strings.Contains(pf, "pass out quick proto {tcp, udp} to 1.1.1.1 port 53") ||
		!strings.Contains(nft, "ip daddr 1.1.1.1 udp dport 53 accept") {
		t.Fatalf("physical resolver was blocked: pf=%s nft=%s", pf, nft)
	}
	if !strings.Contains(pf, "block drop out quick") || !strings.Contains(nft, "udp dport 53 drop") {
		t.Fatal("other resolvers must remain blocked")
	}
}
