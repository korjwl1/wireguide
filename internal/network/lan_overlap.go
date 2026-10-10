package network

import (
	"net"
	"strings"
)

// nonPhysicalIfacePrefixes are interface-name prefixes that never carry the
// machine's real LAN: tunnels, loopback and the macOS/Linux virtual or
// peer-to-peer interfaces. An AllowedIPs range overlapping an address on
// one of the REMAINING (physical) interfaces would, once routed through the
// tunnel, cut the machine off from its own LAN, gateway and resolver.
var nonPhysicalIfacePrefixes = []string{
	"utun", "lo", "gif", "stf", "awdl", "llw", "anpi", "bridge", "vmenet", "ap",
	"wg", "tun", "tap", "ipsec", "ppp",
	// Hypervisor/container virtual NICs (Parallels, VMware, VirtualBox,
	// Docker, libvirt, Hyper-V vEthernet).
	"vnic", "vmnet", "vboxnet", "docker", "br-", "veth", "virbr",
}

// LocalPhysicalAddrs returns the IPv4/IPv6 addresses (with their on-link
// prefix) currently assigned to UP, non-loopback, non-tunnel, non-virtual
// interfaces (link-local excluded). IPNet.IP is the interface address and
// IPNet.Mask its subnet mask. A package var so tests can inject a set.
var LocalPhysicalAddrs = defaultLocalPhysicalAddrs

func defaultLocalPhysicalAddrs() []*net.IPNet {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []*net.IPNet
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isNonPhysicalIfaceName(ifi.Name) {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP == nil {
				continue
			}
			if ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() || ipn.IP.IsLinkLocalMulticast() {
				continue
			}
			out = append(out, ipn)
		}
	}
	return out
}

func isNonPhysicalIfaceName(name string) bool {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "wireguide") || strings.Contains(lower, "wireguard") {
		return true
	}
	for _, p := range nonPhysicalIfacePrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// LocalNetworkOverlap reports whether cidr contains an address currently
// assigned to a physical interface AND is at least as specific as that
// interface's on-link prefix, returning the address. Only such a route
// equals or out-ranks the connected route and would hijack the LAN; a
// broader range (10.0.0.0/8 over a local 10.0.0.0/24, 2000::/3 over a global
// IPv6 address) never shadows it, because the more specific connected route
// still wins. Default and split-default ranges (prefix length 0 or 1) are
// never reported: those are full-tunnel routes, handled separately with an
// endpoint bypass.
func LocalNetworkOverlap(cidr string) (net.IP, bool) {
	return LocalNetworkOverlapIn(cidr, LocalPhysicalAddrs())
}

// LocalNetworkOverlapIn is LocalNetworkOverlap against an explicit snapshot
// of local addresses (from LocalPhysicalAddrs), so callers checking many
// ranges enumerate the interfaces once.
func LocalNetworkOverlapIn(cidr string, locals []*net.IPNet) (net.IP, bool) {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, false
	}
	ones, bits := ipnet.Mask.Size()
	if ones <= 1 {
		return nil, false
	}
	for _, local := range locals {
		if local == nil || local.IP == nil || !ipnet.Contains(local.IP) {
			continue
		}
		lones, lbits := local.Mask.Size()
		if lbits == bits && ones < lones {
			continue
		}
		return local.IP, true
	}
	return nil, false
}

// FirstLocalNetworkOverlap returns the first of cidrs that overlaps a local
// physical address, with the address.
func FirstLocalNetworkOverlap(cidrs []string) (cidr string, addr net.IP, ok bool) {
	for _, c := range cidrs {
		if ip, hit := LocalNetworkOverlap(c); hit {
			return c, ip, true
		}
	}
	return "", nil, false
}
