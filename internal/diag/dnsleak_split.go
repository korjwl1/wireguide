package diag

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
)

// scutilResolver is one "resolver #N" block of `scutil --dns`.
type scutilResolver struct {
	Domain      string // match domain; empty for a default resolver
	Nameservers []string
	Scoped      bool // listed under "DNS configuration (for scoped queries)"
}

// parseScutilDNS parses `scutil --dns` output into resolver blocks. Pure.
func parseScutilDNS(out string) []scutilResolver {
	var blocks []scutilResolver
	scoped := false
	cur := -1
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "DNS configuration"):
			scoped = strings.Contains(line, "scoped")
			cur = -1
		case strings.HasPrefix(line, "resolver #"):
			blocks = append(blocks, scutilResolver{Scoped: scoped})
			cur = len(blocks) - 1
		case cur >= 0:
			key, val, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			key, val = strings.TrimSpace(key), strings.TrimSpace(val)
			switch {
			case key == "domain":
				blocks[cur].Domain = strings.ToLower(strings.TrimSuffix(val, "."))
			case strings.HasPrefix(key, "nameserver["):
				if net.ParseIP(val) != nil {
					blocks[cur].Nameservers = append(blocks[cur].Nameservers, val)
				}
			}
		}
	}
	return blocks
}

// evaluateSplitDNS checks, for every split-DNS match domain, that an
// unscoped supplemental resolver exists whose nameservers include one of the
// tunnel's servers. It returns the domains lacking one. Pure.
func evaluateSplitDNS(blocks []scutilResolver, p domain.DNSEntries) (missing []string) {
	servers := make(map[string]bool, len(p.Servers))
	for _, s := range p.Servers {
		servers[s] = true
	}
	for _, d := range p.Match {
		found := false
		for _, b := range blocks {
			if b.Scoped || b.Domain != strings.ToLower(d) {
				continue
			}
			for _, ns := range b.Nameservers {
				if servers[ns] {
					found = true
				}
			}
		}
		if !found {
			missing = append(missing, d)
		}
	}
	sort.Strings(missing)
	return missing
}

// runSplitDNSCheck is the split-mode variant of the leak test. In split mode
// the system's default resolvers are SUPPOSED to keep answering for ordinary
// names, so probing them proves nothing and reporting them as leaks would be
// a false positive. Instead verify a supplemental resolver exists for each
// match domain. Only macOS exposes that via `scutil --dns`; elsewhere the
// check is skipped (never reported as a leak).
//
// Note that the Go resolver, dig and nslookup read /etc/resolv.conf and
// never see supplemental resolvers; only getaddrinfo callers do.
func runSplitDNSCheck(ctx context.Context, result *DNSLeakResult, p domain.DNSEntries) *DNSLeakResult {
	result.SplitMode = true
	result.Leaked = false
	if runtime.GOOS != "darwin" {
		return result
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "scutil", "--dns").Output()
	if err != nil {
		result.Error = fmt.Sprintf("scutil --dns: %v", err)
		return result
	}
	blocks := parseScutilDNS(string(out))
	vpn := make(map[string]bool, len(p.Servers))
	for _, s := range p.Servers {
		vpn[s] = true
	}
	seen := make(map[string]bool)
	for _, b := range blocks {
		for _, ns := range b.Nameservers {
			if !seen[ns] {
				seen[ns] = true
				result.DNSServers = append(result.DNSServers, DNSServer{IP: ns, IsVPN: vpn[ns]})
			}
		}
	}
	result.MissingMatchDomains = evaluateSplitDNS(blocks, p)
	if len(result.MissingMatchDomains) > 0 {
		result.Error = "split DNS: no supplemental resolver for " + strings.Join(result.MissingMatchDomains, ", ")
	}
	return result
}

// ExpectedDNSForTunnels picks the DNS= entries the leak test should expect
// when several tunnels are connected. A global-mode tunnel overrides system
// DNS, so its servers are what can leak; if any exists, the global
// tunnels' entries plus the split tunnels' server IPs (never their ~match
// tokens, which would switch the test to split mode and mask a global leak). With only split tunnels
// the entries are merged so every match domain is still verified.
func ExpectedDNSForTunnels(perTunnel [][]string) []string {
	var global, split []string
	var splitEntries [][]string
	for _, entries := range perTunnel {
		p := domain.ParseDNSEntries(entries)
		if len(p.Servers) == 0 && len(p.Match) == 0 {
			continue
		}
		if len(p.Match) == 0 {
			global = append(global, entries...)
		} else {
			split = append(split, entries...)
			splitEntries = append(splitEntries, entries)
		}
	}
	if len(global) > 0 {
		// Mixed mode: split tunnels' resolver IPs are legitimate tunnel
		// resolvers (scutil lists them from the supplemental resolver), so
		// add them to the expected set without their ~match tokens, which
		// would flip the test into split mode.
		for _, entries := range splitEntries {
			global = append(global, domain.ParseDNSEntries(entries).Servers...)
		}
		return global
	}
	return split
}
