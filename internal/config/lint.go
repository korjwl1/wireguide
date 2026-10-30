package config

import (
	"fmt"
	"net"
	"runtime"
	"strings"
)

// Diagnostic severities. They map 1:1 onto CodeMirror's lint severities.
const (
	SeverityError   = "error"
	SeverityWarning = "warning"
	SeverityInfo    = "info"
)

// Fix actions understood by the editor's quick-fix handler.
const (
	// FixRemoveDNS deletes the Interface DNS line(s).
	FixRemoveDNS = "remove_dns"
	// FixAppendDNS appends Value (comma separated tokens) to the DNS line.
	FixAppendDNS = "append_dns"
)

// mtuRecommendedMax is the largest MTU that fits WireGuard over a standard
// 1500-byte path with an IPv6 outer header.
const mtuRecommendedMax = 1420

// lintGOOS is the platform the linter reasons about (overridable in tests).
var lintGOOS = runtime.GOOS

// Fix is an optional one-click remedy attached to a Diagnostic.
type Fix struct {
	Label  string `json:"label"`
	Action string `json:"action"`
	Value  string `json:"value,omitempty"`
}

// Diagnostic is one inline editor finding. It is advisory and separate from
// Validate: a config with only warnings or infos is still valid.
type Diagnostic struct {
	// Field is the validator-style location, e.g. "Interface.DNS" or
	// "Peer[0].AllowedIPs". The editor maps it to a line with a key regex.
	Field    string `json:"field"`
	Severity string `json:"severity"`
	// Code is a stable identifier the frontend uses to look up a translated
	// message ("lint.<code>") with Args; Message is the English fallback.
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Args    map[string]string `json:"args,omitempty"`
	Fix     *Fix              `json:"fix,omitempty"`
}

// Lint returns advisory diagnostics for cfg. others holds the other saved
// tunnels keyed by name (exclude the tunnel being edited) for cross-tunnel
// checks; it may be nil and is currently unused. Lint never affects
// Validate/IsValid.
func Lint(cfg *WireGuardConfig, _ map[string]*WireGuardConfig) []Diagnostic {
	if cfg == nil {
		return nil
	}
	var out []Diagnostic

	// Errors mirror the validator's DNS rules, with identical text.
	for _, msg := range dnsErrors(cfg.Interface.DNS) {
		out = append(out, Diagnostic{
			Field:    "Interface.DNS",
			Severity: SeverityError,
			Code:     "dns_error",
			Message:  msg,
		})
	}

	allowed := allAllowedIPs(cfg)
	dns := cfg.Interface.ParseDNS()

	// Warning: global DNS pointing outside the tunnel's routes.
	if len(dns.Match) == 0 && len(dns.Servers) > 0 {
		var outside []string
		for _, srv := range dns.Servers {
			if !ipInAnyCIDR(srv, allowed) {
				outside = append(outside, srv)
			}
		}
		if len(outside) > 0 {
			list := strings.Join(outside, ", ")
			// macOS replaces the DNS of every network service; elsewhere
			// the servers are set on the tunnel adapter, so the wording
			// (and translation key) differs.
			code := "dns_global_outside_adapter"
			if lintGOOS == "darwin" {
				code = "dns_global_outside"
			}
			out = append(out, Diagnostic{
				Field:    "Interface.DNS",
				Severity: SeverityWarning,
				Code:     code,
				Message:  globalOutsideMessage(list),
				Args:     map[string]string{"servers": list},
				Fix:      &Fix{Label: "Remove DNS line", Action: FixRemoveDNS},
			})
		}
	}

	// Warning: .local routing domains collide with mDNS.
	for _, m := range dns.Match {
		lower := strings.ToLower(m)
		if lower == "local" || strings.HasSuffix(lower, ".local") {
			out = append(out, Diagnostic{
				Field:    "Interface.DNS",
				Severity: SeverityWarning,
				Code:     "dns_mdns",
				Message:  fmt.Sprintf("~%s overlaps with mDNS (.local); lookups may not reach the tunnel's DNS server. Prefer a different suffix such as .lan or .corp.", m),
				Args:     map[string]string{"domain": m},
			})
		}
	}

	// Split DNS cannot be applied on Windows, and needs systemd-resolved on
	// Linux; in both cases connecting fails.
	if len(dns.Match) > 0 {
		switch lintGOOS {
		case "windows":
			out = append(out, Diagnostic{
				Field:    "Interface.DNS",
				Severity: SeverityWarning,
				Code:     "dns_split_windows",
				Message:  "Split DNS is not supported on Windows; connecting will fail. Remove the ~ entries to use the servers for all DNS.",
			})
		case "linux":
			out = append(out, Diagnostic{
				Field:    "Interface.DNS",
				Severity: SeverityInfo,
				Code:     "dns_split_linux",
				Message:  "Split DNS on Linux requires systemd-resolved (resolvectl); without it connecting will fail.",
			})
		}
	}

	// Info: MTU above the recommended maximum.
	if cfg.Interface.MTU > mtuRecommendedMax {
		out = append(out, Diagnostic{
			Field:    "Interface.MTU",
			Severity: SeverityInfo,
			Code:     "mtu_high",
			Message:  fmt.Sprintf("MTU %d is above %d and may fragment packets over typical 1500-byte paths.", cfg.Interface.MTU, mtuRecommendedMax),
			Args:     map[string]string{"mtu": fmt.Sprint(cfg.Interface.MTU), "max": fmt.Sprint(mtuRecommendedMax)},
		})
	}

	// Info: LAN-only AllowedIPs with no DNS at all.
	if len(cfg.Interface.DNS) == 0 && len(allowed) > 0 && allPrivate(allowed) {
		gw := "<gateway>"
		if g := GatewayCandidates(allowed); len(g) > 0 {
			gw = g[0]
		}
		out = append(out, Diagnostic{
			Field:    "Interface.DNS",
			Severity: SeverityInfo,
			Code:     "dns_lan_none",
			Message:  fmt.Sprintf("No private-name resolution: add DNS = %s, ~<domain> to resolve names on the remote network.", gw),
			Args:     map[string]string{"gateway": gw},
		})
	}

	// Info: split DNS without reverse zones.
	if len(dns.Match) > 0 && !hasReverseZone(dns.Match) {
		if zones := ReverseZones(allowed); len(zones) > 0 {
			toks := make([]string, len(zones))
			for i, z := range zones {
				toks[i] = "~" + z
			}
			val := strings.Join(toks, ", ")
			out = append(out, Diagnostic{
				Field:    "Interface.DNS",
				Severity: SeverityInfo,
				Code:     "dns_no_reverse",
				Message:  "Split DNS has no reverse zone, so IP-to-name lookups for the remote network use system DNS. Add " + val + " to resolve them through the tunnel.",
				Args:     map[string]string{"zones": val},
				Fix:      &Fix{Label: "Add reverse zones", Action: FixAppendDNS, Value: val},
			})
		}
	}

	return out
}

func allAllowedIPs(cfg *WireGuardConfig) []string {
	var all []string
	for _, p := range cfg.Peers {
		all = append(all, p.AllowedIPs...)
	}
	return all
}

func ipInAnyCIDR(ipStr string, cidrs []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

var privateNets = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"} {
		_, n, _ := net.ParseCIDR(c)
		nets = append(nets, n)
	}
	return nets
}()

// allPrivate reports whether every CIDR lies entirely inside private space.
func allPrivate(cidrs []string) bool {
	found := false
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		found = true
		ones, _ := n.Mask.Size()
		inside := false
		for _, p := range privateNets {
			pOnes, _ := p.Mask.Size()
			if p.Contains(n.IP) && ones >= pOnes {
				inside = true
				break
			}
		}
		if !inside {
			return false
		}
	}
	return found
}

func hasReverseZone(match []string) bool {
	for _, m := range match {
		l := strings.ToLower(m)
		if strings.HasSuffix(l, ".in-addr.arpa") || strings.HasSuffix(l, ".ip6.arpa") {
			return true
		}
	}
	return false
}

// GatewayCandidates derives likely gateway/DNS addresses (x.x.x.1) from
// IPv4 AllowedIPs. Prefixes of /24 or longer yield the .1 of the containing
// /24; shorter prefixes yield the network address + 1. Full-tunnel and
// non-IPv4 entries are skipped. The result is de-duplicated and capped.
func GatewayCandidates(allowed []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range allowed {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		ones, bits := n.Mask.Size()
		base := n.IP.To4()
		if bits != 32 || base == nil || ones == 0 {
			continue
		}
		var gw net.IP
		if ones >= 24 {
			gw = net.IPv4(base[0], base[1], base[2], 1)
		} else {
			gw = net.IPv4(base[0], base[1], base[2], base[3]+1)
		}
		s := gw.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
		if len(out) >= 4 {
			break
		}
	}
	return out
}

// ReverseZones derives in-addr.arpa zones from IPv4 AllowedIPs. A zone must
// never cover more address space than the route, so: a /24 yields its own
// zone; /8 and /16 yield the whole-octet zone; other prefixes of /9 to /23
// yield the covered next-octet sub-zones (172.16.0.0/12 would need 16, so it is
// skipped; 10.1.0.0/22 yields four) only when at most 8. Prefixes longer than
// /24 (such as a single host) and shorter than /8 yield nothing, because the
// smallest zone this derives is a /24 and it would cover more than the route.
// De-duplicated and capped at 8.
func ReverseZones(allowed []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(zone string) {
		if !seen[zone] {
			seen[zone] = true
			out = append(out, zone)
		}
	}
	for _, c := range allowed {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		ones, bits := n.Mask.Size()
		base := n.IP.To4()
		if bits != 32 || base == nil || ones < 8 || ones > 24 {
			continue
		}
		octets := (ones + 7) / 8
		if octets > 3 {
			octets = 3
		}
		count := 1
		if ones < 24 {
			count = 1 << uint(octets*8-ones)
		}
		if count > 8 {
			continue
		}
		for k := 0; k < count; k++ {
			b := [4]int{int(base[0]), int(base[1]), int(base[2]), int(base[3])}
			// Add k to the last zone octet (the network is aligned to count).
			b[octets-1] += k
			parts := make([]string, 0, octets)
			for i := octets - 1; i >= 0; i-- {
				parts = append(parts, fmt.Sprint(b[i]))
			}
			add(strings.Join(parts, ".") + ".in-addr.arpa")
		}
		if len(out) >= 8 {
			out = out[:8]
			break
		}
	}
	return out
}

// globalOutsideMessage words the global-DNS warning per platform: macOS
// replaces the DNS of every network service, other platforms scope it to the
// tunnel adapter.
func globalOutsideMessage(list string) string {
	if lintGOOS == "darwin" {
		return fmt.Sprintf("%s is reached over your normal network, not the tunnel, and replaces system DNS on every network service while connected "+
			"(DNS protection will then allow only this server). Add ~domain to scope it, or remove DNS.", list)
	}
	return fmt.Sprintf("%s is reached over your normal network, not the tunnel, and is used for all DNS while connected. "+
		"Add ~domain to scope it, or remove DNS.", list)
}
