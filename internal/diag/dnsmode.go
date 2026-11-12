package diag

import (
	"strings"

	"github.com/korjwl1/wireguide/internal/domain"
)

// DNS modes derived from a tunnel's [Interface] DNS= entries.
const (
	DNSModeGlobal = "global" // DNS servers, no ~domains: replaces system DNS
	DNSModeSplit  = "split"  // ~domain routing entries: only those domains
	DNSModeSearch = "search" // search domains only: no servers, but system search domains are rewritten
	DNSModeNone   = "none"   // no DNS= servers, search or routing domains
)

// DNSMode is the intended DNS behaviour of a config. It is derived from the
// config alone (intent), not read back from the OS.
type DNSMode struct {
	Mode    string   `json:"mode"`
	Servers []string `json:"servers,omitempty"`
	Domains []string `json:"domains,omitempty"` // ~match domains, "~" stripped
}

// DNSModeOf classifies raw DNS= tokens. Pure.
func DNSModeOf(entries []string) DNSMode {
	p := domain.ParseDNSEntries(entries)
	m := DNSMode{Servers: p.Servers, Domains: p.Match}
	switch {
	case len(p.Match) > 0:
		m.Mode = DNSModeSplit
	case len(p.Servers) > 0:
		m.Mode = DNSModeGlobal
	case len(p.Search) > 0:
		// The helper treats a search-only DNS= line as global and rewrites
		// the system search domains, so it is not "none".
		m.Mode = DNSModeSearch
	default:
		m.Mode = DNSModeNone
	}
	return m
}

// StatusString renders the `ctl status` form: global, split(a,b), search or
// none.
func (m DNSMode) StatusString() string {
	if m.Mode == DNSModeSplit {
		return "split(" + strings.Join(m.Domains, ",") + ")"
	}
	return m.Mode
}
