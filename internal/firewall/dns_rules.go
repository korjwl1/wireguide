package firewall

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
)

// DNSAllow permits DNS (port 53) to Servers through Interface. An empty
// interface permits those specific servers through normal system routing:
// split-tunnel configurations can intentionally use an off-tunnel resolver.
type DNSAllow struct {
	Interface string
	Servers   []string
}

// normalizeDNSAllow drops what can't become a rule: entries whose interface
// fails validIface, and server entries that aren't IP addresses — wg-quick
// configs list search domains in the same DNS= line, and one of those must
// not void the whole rule set. Servers are de-duplicated per interface and
// the result is sorted, so the same tunnels always render the same rules.
func normalizeDNSAllow(allow []DNSAllow, validIface func(string) bool) []DNSAllow {
	byIface := make(map[string][]string)
	seen := make(map[string]map[string]bool)
	for _, a := range allow {
		if a.Interface != "" && !validIface(a.Interface) {
			if a.Interface != "" {
				slog.Warn("DNS protection: skipping invalid interface name", "interface", a.Interface)
			}
			continue
		}
		for _, s := range a.Servers {
			ip := net.ParseIP(strings.TrimSpace(s))
			if ip == nil {
				continue // search domain, or garbage the validator let through
			}
			canon := ip.String()
			if seen[a.Interface] == nil {
				seen[a.Interface] = make(map[string]bool)
			}
			if seen[a.Interface][canon] {
				continue
			}
			seen[a.Interface][canon] = true
			byIface[a.Interface] = append(byIface[a.Interface], canon)
		}
	}
	out := make([]DNSAllow, 0, len(byIface))
	for iface, servers := range byIface {
		sort.Strings(servers)
		out = append(out, DNSAllow{Interface: iface, Servers: servers})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Interface < out[j].Interface })
	return out
}

// dnsAllowServers returns every server across all entries, de-duplicated,
// in entry order.
func dnsAllowServers(allow []DNSAllow) []string {
	seen := make(map[string]bool)
	var out []string
	for _, a := range allow {
		for _, s := range a.Servers {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// pfDNSRules renders normalized entries as pf rules: each tunnel's servers
// pass on that tunnel's interface, loopback resolvers (dnsmasq, local
// filters) pass as they do on Linux, everything else on port 53 drops.
func pfDNSRules(allow []DNSAllow) string {
	var b strings.Builder
	b.WriteString("pass out quick on lo0 proto {tcp, udp} to any port 53\n")
	for _, a := range allow {
		for _, s := range a.Servers {
			scope := ""
			if a.Interface != "" {
				scope = " on " + a.Interface
			}
			fmt.Fprintf(&b, "pass out quick%s proto {tcp, udp} to %s port 53\n", scope, s)
		}
	}
	b.WriteString("block drop out quick proto {tcp, udp} to any port 53\n")
	return b.String()
}

// nftDNSRules renders normalized entries as one nft -f batch for table
// <table>_dns. The batch declares the table (creating it if absent) and
// deletes it before redefining it, all in one transaction: re-running a
// bare `table { chain { … } }` script APPENDS rules to the existing chain,
// which put every later allow behind the first enable's drops.
func nftDNSRules(table string, allow []DNSAllow) string {
	var allowed []string
	for _, a := range allow {
		for _, s := range a.Servers {
			family := "ip"
			if strings.Contains(s, ":") {
				family = "ip6"
			}
			scope := ""
			if a.Interface != "" {
				scope = fmt.Sprintf(" oifname %q", a.Interface)
			}
			allowed = append(allowed,
				fmt.Sprintf("%s daddr %s tcp dport 53%s accept", family, s, scope),
				fmt.Sprintf("%s daddr %s udp dport 53%s accept", family, s, scope))
		}
	}
	return fmt.Sprintf(`add table inet %[1]s_dns
delete table inet %[1]s_dns
table inet %[1]s_dns {
  chain dns_output {
    type filter hook output priority -1; policy accept;
    # Allow DNS to loopback (systemd-resolved stub at 127.0.0.53, local
    # Pi-hole at 127.0.0.1, etc). Without this, systems using
    # systemd-resolved would have ALL DNS blocked.
    oif lo tcp dport 53 accept
    oif lo udp dport 53 accept
    %[2]s
    tcp dport 53 drop
    udp dport 53 drop
  }
}
`, table, strings.Join(allowed, "\n    "))
}
