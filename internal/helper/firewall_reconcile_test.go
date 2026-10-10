package helper

import (
	"reflect"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
)

func testCfg(name string, dns []string, allowed ...string) *domain.WireGuardConfig {
	return &domain.WireGuardConfig{
		Name:      name,
		Interface: domain.InterfaceConfig{DNS: dns},
		Peers:     []domain.PeerConfig{{AllowedIPs: allowed}},
	}
}

func rt(name, iface string, cfg *domain.WireGuardConfig) reconcileTunnel {
	return reconcileTunnel{Name: name, Iface: iface, Cfg: cfg}
}

func TestDesiredDNSPermits(t *testing.T) {
	tests := []struct {
		name    string
		tunnels []reconcileTunnel
		goos    string
		wanted  bool
		want    []firewall.DNSPermit
	}{
		{
			name:    "split route with public resolver is unpinned",
			tunnels: []reconcileTunnel{rt("a", "utun4", testCfg("a", []string{"1.1.1.1"}, "192.168.1.0/24"))},
			goos:    "darwin", wanted: true,
			want: []firewall.DNSPermit{{Interface: "", Server: "1.1.1.1"}},
		},
		{
			name:    "server inside AllowedIPs is pinned",
			tunnels: []reconcileTunnel{rt("a", "utun4", testCfg("a", []string{"192.168.1.1"}, "192.168.1.0/24"))},
			goos:    "darwin", wanted: true,
			want: []firewall.DNSPermit{{Interface: "utun4", Server: "192.168.1.1"}},
		},
		{
			name:    "default-route tunnel pins public resolver",
			tunnels: []reconcileTunnel{rt("a", "utun4", testCfg("a", []string{"1.1.1.1"}, "0.0.0.0/0"))},
			goos:    "darwin", wanted: true,
			want: []firewall.DNSPermit{{Interface: "utun4", Server: "1.1.1.1"}},
		},
		{
			name:    "/1 pair full tunnel pins",
			tunnels: []reconcileTunnel{rt("a", "utun4", testCfg("a", []string{"9.9.9.9"}, "0.0.0.0/1", "128.0.0.0/1"))},
			goos:    "darwin", wanted: true,
			want: []firewall.DNSPermit{{Interface: "utun4", Server: "9.9.9.9"}},
		},
		{
			name: "two tunnels, each with its own servers",
			tunnels: []reconcileTunnel{
				rt("a", "utun4", testCfg("a", []string{"10.0.0.1"}, "10.0.0.0/8")),
				rt("b", "utun5", testCfg("b", []string{"1.1.1.1", "172.16.0.1"}, "172.16.0.0/12")),
			},
			goos: "darwin", wanted: true,
			want: []firewall.DNSPermit{
				{Interface: "", Server: "1.1.1.1"},
				{Interface: "utun4", Server: "10.0.0.1"},
				{Interface: "utun5", Server: "172.16.0.1"},
			},
		},
		{
			name:    "darwin without dnsWanted yields nothing",
			tunnels: []reconcileTunnel{rt("a", "utun4", testCfg("a", []string{"10.0.0.1"}, "0.0.0.0/0"))},
			goos:    "darwin", wanted: false,
			want: nil,
		},
		{
			name:    "windows full tunnel with DNS is auto-protected",
			tunnels: []reconcileTunnel{rt("a", "wg0", testCfg("a", []string{"10.0.0.1"}, "0.0.0.0/0"))},
			goos:    "windows", wanted: false,
			want: []firewall.DNSPermit{{Interface: "wg0", Server: "10.0.0.1"}},
		},
		{
			name:    "windows split tunnel is not auto-protected",
			tunnels: []reconcileTunnel{rt("a", "wg0", testCfg("a", []string{"10.0.0.1"}, "10.0.0.0/8"))},
			goos:    "windows", wanted: false,
			want: nil,
		},
		{
			name:    "split-DNS-only tunnels never trigger protection",
			tunnels: []reconcileTunnel{rt("a", "utun4", testCfg("a", []string{"10.0.0.1", "~corp.example"}, "10.0.0.0/8"))},
			goos:    "darwin", wanted: true,
			want: nil,
		},
		{
			name: "split-DNS tunnel next to a protected tunnel keeps its resolver",
			tunnels: []reconcileTunnel{
				rt("a", "utun4", testCfg("a", []string{"10.0.0.1", "~corp.example"}, "10.0.0.0/8")),
				rt("b", "utun5", testCfg("b", []string{"1.1.1.1"}, "0.0.0.0/0")),
			},
			goos: "darwin", wanted: true,
			want: []firewall.DNSPermit{
				{Interface: "utun4", Server: "10.0.0.1"},
				{Interface: "utun5", Server: "1.1.1.1"},
			},
		},
		{
			name: "split-DNS resolver outside its AllowedIPs gets no permit",
			tunnels: []reconcileTunnel{
				rt("a", "utun4", testCfg("a", []string{"8.8.8.8", "~corp.example"}, "10.0.0.0/8")),
				rt("b", "utun5", testCfg("b", []string{"1.1.1.1"}, "0.0.0.0/0")),
			},
			goos: "darwin", wanted: true,
			want: []firewall.DNSPermit{{Interface: "utun5", Server: "1.1.1.1"}},
		},
		{
			name:    "search-domain entries are ignored",
			tunnels: []reconcileTunnel{rt("a", "utun4", testCfg("a", []string{"corp.lan", "10.0.0.1", "lan"}, "10.0.0.0/8"))},
			goos:    "darwin", wanted: true,
			want: []firewall.DNSPermit{{Interface: "utun4", Server: "10.0.0.1"}},
		},
		{
			name:    "search-domain-only tunnel is not protected",
			tunnels: []reconcileTunnel{rt("a", "utun4", testCfg("a", []string{"corp.lan"}, "0.0.0.0/0"))},
			goos:    "darwin", wanted: true,
			want: nil,
		},
		{
			name: "tunnels without iface or config are skipped",
			tunnels: []reconcileTunnel{
				rt("a", "", testCfg("a", []string{"10.0.0.1"}, "0.0.0.0/0")),
				rt("b", "utun5", nil),
			},
			goos: "darwin", wanted: true,
			want: nil,
		},
		{
			name: "duplicates across tunnels are deduped",
			tunnels: []reconcileTunnel{
				rt("a", "utun4", testCfg("a", []string{"1.1.1.1"}, "192.168.1.0/24")),
				rt("b", "utun5", testCfg("b", []string{"1.1.1.1"}, "192.168.2.0/24")),
			},
			goos: "darwin", wanted: true,
			want: []firewall.DNSPermit{{Interface: "", Server: "1.1.1.1"}},
		},
		{
			name:    "v4 split plus ::/0 with v4 resolver is unpinned",
			tunnels: []reconcileTunnel{rt("a", "utun9", testCfg("a", []string{"1.1.1.1"}, "192.168.50.0/24", "::/0"))},
			goos:    "darwin", wanted: true,
			want: []firewall.DNSPermit{{Interface: "", Server: "1.1.1.1"}},
		},
		{
			name:    "0.0.0.0/0 with v6-only resolver is unpinned",
			tunnels: []reconcileTunnel{rt("a", "utun9", testCfg("a", []string{"2606:4700:4700::1111"}, "0.0.0.0/0"))},
			goos:    "darwin", wanted: true,
			want: []firewall.DNSPermit{{Interface: "", Server: "2606:4700:4700::1111"}},
		},
		{
			name:    "windows full tunnel with split DNS is not auto-protected",
			tunnels: []reconcileTunnel{rt("a", "wg0", testCfg("a", []string{"10.0.0.1", "~corp"}, "0.0.0.0/0"))},
			goos:    "windows", wanted: false,
			want: nil,
		},
		{
			name:    "windows /1-pair tunnel is not auto-protected",
			tunnels: []reconcileTunnel{rt("a", "wg0", testCfg("a", []string{"10.0.0.1"}, "0.0.0.0/1", "128.0.0.0/1"))},
			goos:    "windows", wanted: false,
			want: nil,
		},
		{
			name:    "no tunnels",
			tunnels: nil,
			goos:    "darwin", wanted: true,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := desiredDNSPermits(tt.tunnels, tt.goos, tt.wanted)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v want %+v", got, tt.want)
			}
		})
	}
}
