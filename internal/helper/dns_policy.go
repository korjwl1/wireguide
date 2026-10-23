package helper

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// resolverPermits follows the longest matching installed AllowedIPs prefix
// across the connected set. A public resolver outside every tunnel is allowed
// by address without an interface restriction. Equal-prefix tunnel routes
// permit both interfaces so the kernel can choose by its route metrics.
// Table=off supplies no managed routes and must not imply interface pinning.
func resolverPermits(cfgs map[string]*domain.WireGuardConfig, statuses []*tunnel.ConnectionStatus) []firewall.DNSAllow {
	type path struct {
		iface string
		net   netip.Prefix
	}
	var paths []path
	servers := make(map[netip.Addr]bool)
	for _, st := range statuses {
		if st == nil || st.State != domain.StateConnected || st.InterfaceName == "" {
			continue
		}
		cfg := cfgs[st.TunnelName]
		if cfg == nil {
			continue
		}
		for _, raw := range cfg.Interface.DNS {
			if ip, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil && ip.Zone() == "" {
				servers[ip.Unmap()] = true
			}
		}
		if strings.EqualFold(cfg.Interface.Table, "off") {
			continue
		}
		for _, peer := range cfg.Peers {
			for _, raw := range peer.AllowedIPs {
				if prefix, err := netip.ParsePrefix(raw); err == nil {
					paths = append(paths, path{st.InterfaceName, prefix.Masked()})
				}
			}
		}
	}
	byIface := make(map[string][]string)
	for server := range servers {
		best := -1
		ifaces := make(map[string]bool)
		for _, p := range paths {
			if !p.net.Contains(server) || p.net.Bits() < best {
				continue
			}
			if p.net.Bits() > best {
				clear(ifaces)
				best = p.net.Bits()
			}
			ifaces[p.iface] = true
		}
		if len(ifaces) == 0 {
			ifaces[""] = true
		}
		for iface := range ifaces {
			byIface[iface] = append(byIface[iface], server.String())
		}
	}
	var allow []firewall.DNSAllow
	for iface, servers := range byIface {
		sort.Strings(servers)
		allow = append(allow, firewall.DNSAllow{Interface: iface, Servers: servers})
	}
	sort.Slice(allow, func(i, j int) bool { return allow[i].Interface < allow[j].Interface })
	return allow
}
