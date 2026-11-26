package diag

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
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
	Scoped      bool // listed under "DNS configuration (for scoped queries)" or flagged Scoped
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
			case key == "flags":
				if strings.Contains(val, "Scoped") {
					blocks[cur].Scoped = true
				}
			case strings.HasPrefix(key, "nameserver["):
				if _, err := netip.ParseAddr(val); err == nil {
					blocks[cur].Nameservers = append(blocks[cur].Nameservers, val)
				}
			}
		}
	}
	return blocks
}

// darwinDefaultResolvers returns the nameservers of the unscoped resolvers
// without a match domain — the resolvers ordinary names use. Scoped
// per-interface resolvers and supplemental (per-domain) resolvers, including
// other apps' such as a ts.net resolver, are not default resolvers. Every
// macOS global check takes its probe set from here, so the verdict does not
// depend on whether a split tunnel is also up. Pure.
func darwinDefaultResolvers(blocks []scutilResolver) []string {
	var defaults []string
	seen := map[string]bool{}
	for _, b := range blocks {
		if b.Scoped || b.Domain != "" {
			continue
		}
		for _, ns := range b.Nameservers {
			if !seen[ns] {
				seen[ns] = true
				defaults = append(defaults, ns)
			}
		}
	}
	return defaults
}

// evaluateSplitDNS checks, for every split-DNS match domain, that an
// unscoped supplemental resolver exists whose nameservers belong to the domain's configured servers. It returns the domains lacking one. Pure.
func evaluateSplitDNS(blocks []scutilResolver, p domain.DNSEntries) []string {
	return evaluateSplitDNSPlans(blocks, []domain.DNSEntries{p})
}

func evaluateSplitDNSPlans(blocks []scutilResolver, plans []domain.DNSEntries) (missing []string) {
	for _, c := range splitDomainChecks(blocks, plans) {
		if !c.Registered {
			missing = append(missing, c.Domain)
		}
	}
	return missing
}

// splitDomainChecks is the per-domain form of the ownership check: one row
// per match or search domain of the plans, sorted by domain. Registered means
// an unscoped supplemental resolver exists for the domain and every one of its
// nameservers is a configured server of a tunnel claiming that domain.
// Resolver is the nameserver the system routes the domain to (an expected one
// when registered, otherwise the first unexpected one, "" when there is none).
// The leak test's missing-domain list and its per-domain rows both derive
// from this one function so they cannot disagree. Pure.
func splitDomainChecks(blocks []scutilResolver, plans []domain.DNSEntries) []DomainCheck {
	expected := make(map[string]map[string]bool)
	search := make(map[string]bool)
	for _, p := range plans {
		add := func(d string, isSearch bool) {
			d = strings.ToLower(d)
			if expected[d] == nil {
				expected[d] = make(map[string]bool)
			}
			if isSearch {
				search[d] = true
			}
			for _, s := range p.Servers {
				if ip := net.ParseIP(s); ip != nil {
					expected[d][ip.String()] = true
				}
			}
		}
		for _, d := range p.Match {
			add(d, false)
		}
		for _, d := range p.Search {
			add(d, true)
		}
	}
	checks := make([]DomainCheck, 0, len(expected))
	for d, servers := range expected {
		c := DomainCheck{Domain: d}
		found := false
		wrong := false
		for _, b := range blocks {
			if b.Scoped || b.Domain != d {
				continue
			}
			for _, ns := range b.Nameservers {
				ip := net.ParseIP(ns)
				if ip != nil && servers[ip.String()] {
					if !found {
						c.Resolver = ns
					}
					found = true
				} else {
					if !found && !wrong {
						c.Resolver = ns
					}
					wrong = true
				}
			}
		}
		c.Registered = found && !wrong
		// A domain that is both a match and a search entry is a match
		// domain for display; only pure search entries are flagged.
		c.Search = search[d] && !containsFold(plansMatch(plans), d)
		checks = append(checks, c)
	}
	sort.Slice(checks, func(i, j int) bool { return checks[i].Domain < checks[j].Domain })
	return checks
}

func plansMatch(plans []domain.DNSEntries) []string {
	var out []string
	for _, p := range plans {
		out = append(out, p.Match...)
	}
	return out
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// runSplitDNSCheck is the split-mode variant of the leak test. In split mode
// the system's default resolvers are SUPPOSED to keep answering for ordinary
// names, so probing them proves nothing and reporting them as leaks would be
// a false positive. Instead verify a supplemental resolver exists for each
// match domain. Only macOS exposes that via `scutil --dns`; elsewhere the
// check reports verification unavailable.
//
// Note that the Go resolver, dig and nslookup read /etc/resolv.conf and
// never see supplemental resolvers; only getaddrinfo callers do.
func runSplitDNSCheck(ctx context.Context, result *DNSLeakResult, p domain.DNSEntries) *DNSLeakResult {
	return runSplitDNSChecks(ctx, result, []domain.DNSEntries{p})
}

func runSplitDNSChecks(ctx context.Context, result *DNSLeakResult, plans []domain.DNSEntries) *DNSLeakResult {
	if runtime.GOOS != "darwin" {
		result.Error = "split DNS configuration verification is unavailable on this platform"
		return result
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "scutil", "--dns").Output()
	if err != nil {
		result.Error = fmt.Sprintf("scutil --dns: %v", err)
		return result
	}
	return evaluateSplitDNSResult(result, plans, parseScutilDNS(string(out)))
}

func evaluateSplitDNSResult(result *DNSLeakResult, plans []domain.DNSEntries, blocks []scutilResolver) *DNSLeakResult {
	vpn := make(map[string]bool)
	for _, p := range plans {
		for _, s := range p.Servers {
			vpn[s] = true
		}
	}
	seen := make(map[string]bool)
	for _, server := range result.DNSServers {
		seen[server.IP] = true
	}
	for _, b := range blocks {
		for _, ns := range b.Nameservers {
			if !seen[ns] {
				seen[ns] = true
				scope := ""
				if b.Scoped {
					scope = "scoped"
				} else if b.Domain != "" {
					scope = "supplemental"
				}
				result.DNSServers = append(result.DNSServers, DNSServer{IP: ns, IsVPN: vpn[ns], Scope: scope})
			}
		}
	}
	result.Domains = splitDomainChecks(blocks, plans)
	for _, c := range result.Domains {
		if !c.Registered {
			result.MissingMatchDomains = append(result.MissingMatchDomains, c.Domain)
		}
	}
	if len(result.MissingMatchDomains) > 0 {
		message := "split DNS: no supplemental resolver for " + strings.Join(result.MissingMatchDomains, ", ")
		if result.Error != "" {
			result.Error += "; " + message
		} else {
			result.Error = message
		}
	}
	return result
}

// RunDNSLeakTestForTunnels preserves each domain's resolver ownership.
// Mixed mode checks both the global resolver set and supplemental domains.
func RunDNSLeakTestForTunnels(perTunnel [][]string) *DNSLeakResult {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var plans []domain.DNSEntries
	hasGlobal := false
	for _, entries := range perTunnel {
		p := domain.ParseDNSEntries(entries)
		if len(p.Match) > 0 {
			plans = append(plans, p)
		} else if len(p.Servers) > 0 {
			hasGlobal = true
		}
	}
	if len(plans) == 0 {
		return RunDNSLeakTestContext(ctx, ExpectedDNSForTunnels(perTunnel))
	}
	if hasGlobal && runtime.GOOS == "darwin" {
		// One OS snapshot: supplemental resolvers must never expand the set of
		// allowed DEFAULT resolvers, even when both share the same server IP.
		out, err := exec.CommandContext(ctx, "scutil", "--dns").Output()
		if err != nil {
			return &DNSLeakResult{Error: fmt.Sprintf("scutil --dns: %v", err)}
		}
		blocks := parseScutilDNS(string(out))
		defaults := darwinDefaultResolvers(blocks)
		result := runGlobalDNSCheck(ctx, ExpectedDNSForTunnels(perTunnel), func() ([]string, error) { return defaults, nil })
		return evaluateSplitDNSResult(result, plans, blocks)
	}
	result := &DNSLeakResult{SplitMode: !hasGlobal}
	if hasGlobal {
		result = RunDNSLeakTestContext(ctx, ExpectedDNSForTunnels(perTunnel))
	}
	return runSplitDNSChecks(ctx, result, plans)
}

// ExpectedDNSForTunnels returns only global entries when global DNS is in
// use. Supplemental ownership is checked separately from default resolvers.
func ExpectedDNSForTunnels(perTunnel [][]string) []string {
	var global, split []string
	for _, entries := range perTunnel {
		p := domain.ParseDNSEntries(entries)
		if len(p.Match) > 0 {
			split = append(split, entries...)
		} else if len(p.Servers) > 0 {
			global = append(global, entries...)
		}
	}
	if len(global) > 0 {
		return global
	}
	return split
}
