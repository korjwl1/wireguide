package diag

import (
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestResolvedDefaultResolversRespectRootAndDomainRoutes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		snapshot resolvedSnapshot
		want     []string
	}{
		{"root VPN excludes physical and global", resolvedSnapshot{Global: []string{"9.9.9.9"}, Links: []resolvedLink{
			{Servers: []string{"192.168.1.1"}, DefaultRoute: true},
			{Servers: []string{"10.0.0.53"}, Domains: []string{"."}, DefaultRoute: true},
			{Servers: []string{"10.1.0.53"}, Domains: []string{"corp.example"}},
		}}, []string{"10.0.0.53"}},
		{"default links and global", resolvedSnapshot{Global: []string{"9.9.9.9"}, Links: []resolvedLink{
			{Servers: []string{"192.168.1.1"}, DefaultRoute: true},
			{Servers: []string{"10.1.0.53"}, Domains: []string{"corp.example"}},
		}}, []string{"9.9.9.9", "192.168.1.1"}},
		{"tied root owners both matter", resolvedSnapshot{Global: []string{"9.9.9.9"}, GlobalDomains: []string{"."}, Links: []resolvedLink{
			{Servers: []string{"10.0.0.53"}, Domains: []string{"."}},
		}}, []string{"9.9.9.9", "10.0.0.53"}},
		{"fallback only without configured servers", resolvedSnapshot{Fallback: []string{"9.9.9.9"}}, []string{"9.9.9.9"}},
		{"no fallback for domain-only configuration", resolvedSnapshot{Fallback: []string{"9.9.9.9"}, Links: []resolvedLink{
			{Servers: []string{"10.0.0.53"}, Domains: []string{"corp.example"}},
		}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.snapshot.defaultResolvers(); !slices.Equal(got, tc.want) {
				t.Fatalf("resolvers=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestLinuxStubResolverIsAttributedToUpstreams(t *testing.T) {
	read := func() (resolvedSnapshot, error) { return resolvedSnapshot{Global: []string{"10.0.0.53"}}, nil }
	got, err := linuxResolverUpstreams(strings.NewReader("nameserver 127.0.0.53\nnameserver 127.0.0.54\n"), read)
	if err != nil || !slices.Equal(got, []string{"10.0.0.53"}) {
		t.Fatalf("stub attribution: %v %v", got, err)
	}
	called := false
	got, err = linuxResolverUpstreams(strings.NewReader("nameserver 10.0.0.53\n"), func() (resolvedSnapshot, error) {
		called = true
		return resolvedSnapshot{}, errors.New("not installed")
	})
	if err != nil || called || !slices.Equal(got, []string{"10.0.0.53"}) {
		t.Fatal("direct resolvers incorrectly required systemd-resolved")
	}
	for _, addr := range []string{"127.0.0.53", "127.0.0.1"} {
		got, err := linuxResolverUpstreams(strings.NewReader("nameserver "+addr+"\n"), func() (resolvedSnapshot, error) {
			return resolvedSnapshot{}, errors.New("unavailable")
		})
		if err == nil || len(got) != 0 {
			t.Fatal("unattributable local proxy was given a false leak/safety verdict")
		}
	}
}

func TestResolvedIPv6LinkLocalRetainsZone(t *testing.T) {
	ip, err := resolvedAddress(10, net.ParseIP("fe80::53").To16(), "3")
	if err != nil || ip != "fe80::53%3" {
		t.Fatalf("link-local DNS=%q err=%v", ip, err)
	}
	if _, err := resolvedAddress(10, net.ParseIP("fe80::53").To16(), ""); err == nil {
		t.Fatal("link-local DNS without an interface accepted")
	}
}

func TestScopedResolverZoneSurvivesWithoutFalseLeakBadge(t *testing.T) {
	blocks := parseScutilDNS("DNS configuration\nresolver #1\n nameserver[0] : fe80::53%en0\n flags : Scoped, Request AAAA records\n")
	if len(blocks) != 1 || !blocks[0].Scoped || !slices.Equal(blocks[0].Nameservers, []string{"fe80::53%en0"}) {
		t.Fatalf("scoped IPv6 resolver lost: %+v", blocks)
	}
	result := evaluateSplitDNSResult(&DNSLeakResult{}, nil, blocks)
	if result.Leaked || len(result.DNSServers) != 1 || result.DNSServers[0].Leaked || result.DNSServers[0].Scope != "scoped" {
		t.Fatalf("scoped resolver reported as a leak: %+v", result)
	}
}

func TestResolvedDBusPropertySignaturesDecode(t *testing.T) {
	props := map[string]dbus.Variant{
		"DNS":     dbus.MakeVariant([][]any{{int32(3), int32(2), []byte{10, 0, 0, 53}}}),
		"Domains": dbus.MakeVariant([][]any{{int32(3), ".", true}}),
	}
	var dns []resolvedDNSAddress
	var domains []resolvedGlobalDomain
	if err := resolvedProperty(props, "DNS", &dns); err != nil || len(dns) != 1 || dns[0].Index != 3 || !slices.Equal(dns[0].Address, []byte{10, 0, 0, 53}) {
		t.Fatalf("manager DNS tuple: %+v %v", dns, err)
	}
	if err := resolvedProperty(props, "Domains", &domains); err != nil || len(domains) != 1 || domains[0].Name != "." || !domains[0].RoutingOnly {
		t.Fatalf("manager domain tuple: %+v %v", domains, err)
	}
	if err := resolvedProperty(props, "DefaultRoute", new(bool)); err == nil {
		t.Fatal("missing policy field was silently treated as false")
	}
}
