package app

import (
	"github.com/korjwl1/wireguide/internal/diag"
	"github.com/korjwl1/wireguide/internal/ipc"
)

// DNSLeakResult mirrors diag.DNSLeakResult for Wails JSON serialisation.
type DNSLeakResult struct {
	Leaked     bool        `json:"leaked"`
	DNSServers []DNSServer `json:"dns_servers"`
	TestDomain string      `json:"test_domain"`
	Error      string      `json:"error,omitempty"`

	SplitMode           bool     `json:"split_mode,omitempty"`
	MissingMatchDomains []string `json:"missing_match_domains,omitempty"`
}

// DNSServer mirrors diag.DNSServer.
type DNSServer struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	IsVPN    bool   `json:"is_vpn"`
}

// RouteEntry mirrors diag.RouteEntry for Wails JSON serialisation.
type RouteEntry struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Flags       string `json:"flags"`
}

// RunDNSLeakTest performs a DNS leak test using the currently active tunnel's
// DNS servers as the expected (VPN) resolvers. If no tunnel is connected, the
// expected set is empty — all detected resolvers will be flagged as leaks.
func (s *TunnelService) RunDNSLeakTest() (*DNSLeakResult, error) {
	// Best-effort: find the active tunnel's DNS config to know which resolvers
	// are expected to be in use. Ignore IPC errors — an empty expected set is
	// still a valid (conservative) test.
	var expectedDNS []string
	var resp ipc.ActiveTunnelsResponse
	if err := s.call(ipc.MethodActiveTunnels, nil, &resp); err == nil {
		var perTunnel [][]string
		for _, name := range resp.Names {
			if cfg, err := s.tunnelStore.Load(name); err == nil && cfg != nil {
				perTunnel = append(perTunnel, cfg.Interface.DNS)
			}
		}
		expectedDNS = diag.ExpectedDNSForTunnels(perTunnel)
	}

	r := diag.RunDNSLeakTest(expectedDNS)
	out := &DNSLeakResult{
		Leaked:     r.Leaked,
		TestDomain: r.TestDomain,
		Error:      r.Error,

		SplitMode:           r.SplitMode,
		MissingMatchDomains: r.MissingMatchDomains,
	}
	for _, srv := range r.DNSServers {
		out.DNSServers = append(out.DNSServers, DNSServer{
			IP:       srv.IP,
			Hostname: srv.Hostname,
			IsVPN:    srv.IsVPN,
		})
	}
	return out, nil
}

// GetRoutingTable returns the current OS routing table.
func (s *TunnelService) GetRoutingTable() ([]RouteEntry, error) {
	entries, err := diag.GetRoutingTable()
	if err != nil {
		return nil, err
	}
	out := make([]RouteEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, RouteEntry{
			Destination: e.Destination,
			Gateway:     e.Gateway,
			Interface:   e.Interface,
			Flags:       e.Flags,
		})
	}
	return out, nil
}
