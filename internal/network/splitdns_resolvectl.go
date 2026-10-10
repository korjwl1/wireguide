package network

import "github.com/korjwl1/wireguide/internal/domain"

// resolvectlSplitCommands returns the resolvectl argument lists (without the
// "resolvectl" program name) that configure a split-DNS link: the tunnel's
// servers, a routing-only domain list, and no default route. Match domains
// keep their "~" (routing only); plain split domains are passed bare so they
// also act as search domains. The catch-all "~." is deliberately never added.
// The last command (default-route) is best-effort: older systemd lacks it.
// Pure so it can be tested on any platform.
func resolvectlSplitCommands(iface string, p domain.DNSEntries) [][]string {
	dns := append([]string{"dns", iface}, p.Servers...)
	doms := []string{"domain", iface}
	for _, d := range p.Match {
		doms = append(doms, "~"+d)
	}
	doms = append(doms, p.Search...)
	return [][]string{dns, doms, {"default-route", iface, "no"}}
}
