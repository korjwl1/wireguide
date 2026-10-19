package domain

import (
	"net"
	"strings"
)

// DNSEntries is the parsed form of an [Interface] DNS= list, which mixes
// resolver IPs, search domains and "~domain" routing (match) domains.
type DNSEntries struct {
	Servers []string // IP literals, in config order
	Search  []string // plain search domains
	Match   []string // "~domain" routing domains, with the "~" stripped
}

// ParseDNSEntries splits raw DNS= tokens into servers, search domains and
// match domains. Tokens are trimmed, order is preserved and duplicates are
// dropped case-insensitively. Malformed match tokens (empty, "." or a second
// "~") are skipped silently. Pure: no logging.
func ParseDNSEntries(entries []string) DNSEntries {
	var out DNSEntries
	seenServers := make(map[string]struct{})
	seenSearch := make(map[string]struct{})
	seenMatch := make(map[string]struct{})
	add := func(list *[]string, seen map[string]struct{}, v string) {
		key := strings.ToLower(v)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		*list = append(*list, v)
	}
	for _, raw := range entries {
		tok := strings.TrimSpace(raw)
		if tok == "" {
			continue
		}
		if net.ParseIP(tok) != nil {
			add(&out.Servers, seenServers, tok)
			continue
		}
		if strings.HasPrefix(tok, "~") {
			dom := strings.TrimSpace(tok[1:])
			if dom == "" || dom == "." || strings.HasPrefix(dom, "~") {
				continue
			}
			add(&out.Match, seenMatch, dom)
			continue
		}
		add(&out.Search, seenSearch, tok)
	}
	return out
}

// ParseDNS parses the interface's DNS= entries.
func (i InterfaceConfig) ParseDNS() DNSEntries {
	return ParseDNSEntries(i.DNS)
}

// IsSplitDNS reports whether the interface declares any "~domain" routing
// domains, i.e. DNS should only be sent to its servers for those domains.
func (i InterfaceConfig) IsSplitDNS() bool {
	return len(i.ParseDNS().Match) > 0
}

// OwnsDefaultRoute returns true if the config captures the default route:
// any peer carries 0.0.0.0/0 or ::/0, or the two halves of a family
// (0.0.0.0/1 + 128.0.0.0/1, ::/1 + 8000::/1). Unlike IsFullTunnel it also
// recognises the wg-quick style "split default" that avoids replacing the
// existing default route.
func (c *WireGuardConfig) OwnsDefaultRoute() bool {
	var v4Lo, v4Hi, v6Lo, v6Hi bool
	for _, peer := range c.Peers {
		for _, ip := range peer.AllowedIPs {
			_, cidr, err := net.ParseCIDR(strings.TrimSpace(ip))
			if err != nil {
				continue
			}
			ones, bits := cidr.Mask.Size()
			switch {
			case ones == 0 && (bits == 32 || bits == 128):
				return true
			case ones == 1 && bits == 32:
				if cidr.IP.Equal(net.IPv4zero) {
					v4Lo = true
				} else if cidr.IP.Equal(net.IPv4(128, 0, 0, 0)) {
					v4Hi = true
				}
			case ones == 1 && bits == 128:
				if cidr.IP.Equal(net.ParseIP("::")) {
					v6Lo = true
				} else if cidr.IP.Equal(net.ParseIP("8000::")) {
					v6Hi = true
				}
			}
		}
	}
	return (v4Lo && v4Hi) || (v6Lo && v6Hi)
}
