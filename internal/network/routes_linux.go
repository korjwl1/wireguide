//go:build linux

package network

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
)

func (m *LinuxManager) AddRoutes(ifaceName string, allowedIPs []string, fullTunnel bool, endpointIPs []string, tableCfg string, fwmarkCfg string) error {
	// H8: Parse Table config
	table, fwmark := resolveTableAndFwMark(tableCfg, fwmarkCfg)

	// Table = off → skip routing entirely
	if table == -1 {
		m.table = -1
		m.tableSet = true
		slog.Info("Table=off, skipping route installation")
		return nil
	}

	m.fwmark = fwmark
	m.table = table

	if fullTunnel {
		return m.addFullTunnelRoutesWithConfig(ifaceName, endpointIPs, table, fwmark)
	}

	// Split-tunnel routes: wg-quick adds these to the MAIN table (no table arg)
	// when Table=auto or Table="" (the default). Only when the user explicitly
	// sets Table=<number> do routes go to a custom table. This is because
	// wg-quick's add_route() only delegates to add_default() (which uses a
	// custom table) for /0 routes — all other routes go to main.
	m.tableSet = true
	explicitTable := strings.TrimSpace(tableCfg)
	useExplicitTable := explicitTable != "" && !strings.EqualFold(explicitTable, "auto")
	if !useExplicitTable {
		// The routes below go to the MAIN table (no table arg), but
		// resolveTableAndFwMark stored the resolved auto table (e.g.
		// 51820) in m.table — RemoveRoutes would then delete from a
		// table the routes were never added to, silently leaking them
		// on disconnect/reconfigure. Record main (0) as where these
		// split routes actually live, matching what crash recovery
		// derives from the raw "auto"/"" config string.
		m.table = 0
	}

	for _, cidr := range allowedIPs {
		// Skip /0 entries in split-tunnel — they should have been caught
		// by fullTunnel=true, but guard against misconfiguration.
		if cidr == "0.0.0.0/0" || cidr == "::/0" {
			continue
		}
		proto := "-4"
		if strings.Contains(cidr, ":") {
			proto = "-6"
		}
		// Idempotency check: skip if a route for this CIDR already exists
		// on this interface (matches wg-quick's `ip route show dev $INTERFACE match $1`).
		existingOut, _ := runOut("ip", proto, "route", "show", "dev", ifaceName, "match", cidr)
		if strings.TrimSpace(string(existingOut)) != "" {
			continue
		}
		if useExplicitTable {
			tableStr := explicitTable
			if err := runCmd("ip", proto, "route", "add", cidr, "dev", ifaceName, "table", tableStr); err != nil {
				return fmt.Errorf("adding route %s to table %s: %w", cidr, tableStr, err)
			}
		} else {
			// Table=auto or empty → main table (no table argument), matching wg-quick.
			if err := runCmd("ip", proto, "route", "add", cidr, "dev", ifaceName); err != nil {
				return fmt.Errorf("adding route %s: %w", cidr, err)
			}
		}
	}
	return nil
}

// parseIntOrHex parses a string as decimal or hex (0x prefix).
func parseIntOrHex(s string) (int, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		val, err := strconv.ParseInt(s[2:], 16, 64)
		return int(val), err
	}
	val, err := strconv.Atoi(s)
	return val, err
}

// findFreeTable returns tableNum if both IPv4 and IPv6 route tables are empty,
// otherwise increments until finding a free table (up to tableNum+100).
// This matches wg-quick's approach: check `ip -4 route show table $table` and
// `ip -6 route show table $table` for non-empty output.
func findFreeTable(tableNum int) int {
	for i := 0; i < 100; i++ {
		candidate := tableNum + i
		candidateStr := strconv.Itoa(candidate)
		v4Out, _ := runOut("ip", "-4", "route", "show", "table", candidateStr)
		v6Out, _ := runOut("ip", "-6", "route", "show", "table", candidateStr)
		if strings.TrimSpace(string(v4Out)) == "" && strings.TrimSpace(string(v6Out)) == "" {
			return candidate
		}
	}
	return tableNum // fallback
}

// ruleExists checks whether an `ip rule` listing contains the given
// marker line (a full or substring match against the output of
// `ip <proto> rule show`). We narrow the match against a unique priority
// number to avoid false positives from other tools (docker, libvirt,
// systemd-networkd) that may use overlapping table numbers but different
// priorities.
func ruleExists(proto string, marker string) bool {
	out, err := runOut("ip", proto, "rule", "show")
	if err != nil {
		return false
	}
	return strings.Contains(string(out), marker)
}

func (m *LinuxManager) addFullTunnelRoutesWithConfig(ifaceName string, endpoints []string, table, fwmark int) error {
	// wg-quick-compatible fwmark-based policy routing:
	// 1. Set fwmark on WireGuard socket so its encrypted packets bypass the policy rule
	// 2. Add default route in WG routing table (both IPv4 and IPv6)
	// 3. Add policy rule: packets NOT marked -> use WG table
	// 4. Suppress main table default route for local subnet lookups

	tableStr := strconv.Itoa(table)
	fwmarkStr := strconv.Itoa(fwmark)

	// Commit table/fwmark immediately so any subsequent rollback via
	// removeFullTunnelRoutes() targets the correct table even when only
	// the early phases ran (C5).
	m.fwmark = fwmark
	m.table = table
	m.tableSet = true

	// rollbackPartial undoes the routes/rules we've installed so far when
	// a downstream step fails. Calls removeFullTunnelRoutes which is a
	// superset of what addFullTunnelRoutes installs — extra deletes against
	// not-yet-installed state are no-ops at the kernel layer (`ip route
	// delete` returns ESRCH which we swallow as best-effort).
	rollbackPartial := func() {
		if err := m.removeFullTunnelRoutes(ifaceName); err != nil {
			slog.Warn("full-tunnel rollback removeFullTunnelRoutes failed", "error", err)
		}
	}

	// Step 1: Set fwmark on WireGuard socket (critical -- without this,
	// encrypted WG packets are unmarked and match the policy rule, creating
	// a routing loop that kills all connectivity).
	if err := runCmd("wg", "set", ifaceName, "fwmark", fwmarkStr); err != nil {
		return fmt.Errorf("setting fwmark on %s: %w", ifaceName, err)
	}

	// Step 2: Default routes in routing table
	if err := runCmd("ip", "route", "add", "default", "dev", ifaceName, "table", tableStr, "proto", "static"); err != nil {
		rollbackPartial()
		return fmt.Errorf("adding IPv4 default route to table %s: %w", tableStr, err)
	}
	// IPv6 default route (if kernel supports it -- errors are non-fatal)
	if err := runCmd("ip", "-6", "route", "add", "default", "dev", ifaceName, "table", tableStr, "proto", "static"); err != nil {
		// LOW: Log IPv6 failures at warn level instead of silently swallowing
		slog.Warn("failed to add IPv6 default route", "table", tableStr, "error", err)
	}

	// Step 3: Policy rules -- unmarked traffic uses WG table.
	// Idempotency: `ip rule add` does NOT detect duplicates; reconnects without
	// clean disconnect (e.g. crash) accumulate identical rules. We tag our
	// rules with explicit priorities so the existence check is precise: a
	// match on "<priority>:" at the start of a rule line is unambiguously
	// our rule, not someone else's that happens to use the same table.
	fwmarkRuleMarker := wgRulePriorityFwmark + ":"
	if !ruleExists("-4", fwmarkRuleMarker) {
		if err := runCmd("ip", "rule", "add", "priority", wgRulePriorityFwmark, "not", "fwmark", fwmarkStr, "table", tableStr); err != nil {
			rollbackPartial()
			return fmt.Errorf("adding IPv4 policy rule: %w", err)
		}
	}
	if !ruleExists("-6", fwmarkRuleMarker) {
		if err := runCmd("ip", "-6", "rule", "add", "priority", wgRulePriorityFwmark, "not", "fwmark", fwmarkStr, "table", tableStr); err != nil {
			slog.Warn("failed to add IPv6 policy rule", "table", tableStr, "error", err)
		}
	}

	// Step 4: Suppress main table default route for local subnet traffic.
	// Same priority-based idempotency as the fwmark rule above.
	suppressRuleMarker := wgRulePrioritySuppress + ":"
	if !ruleExists("-4", suppressRuleMarker) {
		if err := runCmd("ip", "rule", "add", "priority", wgRulePrioritySuppress, "table", "main", "suppress_prefixlength", "0"); err != nil {
			slog.Warn("failed to add IPv4 suppress rule", "error", err)
		}
	}
	if !ruleExists("-6", suppressRuleMarker) {
		if err := runCmd("ip", "-6", "rule", "add", "priority", wgRulePrioritySuppress, "table", "main", "suppress_prefixlength", "0"); err != nil {
			slog.Warn("failed to add IPv6 suppress rule", "error", err)
		}
	}

	// Step 5: Set src_valid_mark sysctl (wg-quick requirement for IPv4 full-tunnel).
	// Without this, reverse path filtering (rp_filter=1, default on Ubuntu/Fedora)
	// drops reply packets whose source address was validated against an interface
	// that doesn't match the fwmark routing decision. This causes intermittent
	// packet loss or complete tunnel failure.
	if data, err := os.ReadFile("/proc/sys/net/ipv4/conf/all/src_valid_mark"); err == nil {
		if strings.TrimSpace(string(data)) != "1" {
			if err := os.WriteFile("/proc/sys/net/ipv4/conf/all/src_valid_mark", []byte("1"), 0644); err != nil {
				slog.Warn("failed to set src_valid_mark sysctl", "error", err)
			}
		}
	}

	// Step 6 (H9): For each peer endpoint, add a /32 (v4) or /128 (v6) host
	// route into the MAIN table. This is technically redundant with the
	// fwmark+policy machinery (encrypted WG packets are marked and skip the WG
	// table) but it makes Fedora/RHEL's IPv6 rp_filter happy. Without this,
	// IPv6 reply packets from the peer endpoint can be dropped by rp_filter
	// because the kernel can't find a more-specific route than the suppressed
	// default in main. wg-quick papers over this by relying on src_valid_mark
	// (IPv4 only); the host route is the documented workaround for IPv6 +
	// firewalld's ipv6_rpfilter.
	for _, ep := range endpoints {
		if ep == "" {
			continue
		}
		ip := net.ParseIP(ep)
		if ip == nil {
			continue
		}
		proto := "-4"
		hostCIDR := ep + "/32"
		if ip.To4() == nil {
			proto = "-6"
			hostCIDR = ep + "/128"
		}
		existing, _ := runOut("ip", proto, "route", "show", hostCIDR)
		if strings.TrimSpace(string(existing)) != "" {
			continue // already a more-specific route present
		}
		// Use `ip route add throw` so the kernel knows to skip the WG table
		// for these IPs and fall back to main. throw is the standard nft
		// idiom for "no route to here in this table, try the next rule".
		if err := runCmd("ip", proto, "route", "add", "throw", hostCIDR, "table", tableStr); err != nil {
			slog.Debug("endpoint throw route add failed (may already exist)", "ep", ep, "error", err)
		} else {
			m.endpointThrowRoutes = append(m.endpointThrowRoutes, hostCIDR)
		}
	}

	return nil
}

func (m *LinuxManager) RemoveRoutes(ifaceName string, allowedIPs []string, fullTunnel bool) error {
	if m.tableSet && m.table == -1 {
		return nil
	}
	if fullTunnel {
		return m.removeFullTunnelRoutes(ifaceName)
	}
	// M9: Log errors instead of discarding
	// Use the same table that was used to add the routes.
	tableStr := ""
	if m.tableSet && m.table != 0 {
		tableStr = strconv.Itoa(m.table)
	}
	for _, cidr := range allowedIPs {
		args := splitRouteDeleteArgs(ifaceName, cidr, tableStr)
		err := runCmd("ip", args...)
		if err != nil {
			slog.Warn("failed to remove route", "cidr", cidr, "iface", ifaceName, "table", tableStr, "error", err)
		}
	}
	return nil
}

// findOwnedTable scans candidate wg-quick table numbers (51820..51919) for
// one that holds a default route via the given interface. Returns the
// canonical default "51820" if nothing matches — safe because the subsequent
// `ip route delete default table 51820 dev ifaceName` simply errors out on
// no-match, which we log as best-effort.
func (m *LinuxManager) findOwnedTable(ifaceName string) string {
	for i := 0; i < 100; i++ {
		candidate := strconv.Itoa(51820 + i)
		out, err := runOut("ip", "route", "show", "default", "dev", ifaceName, "table", candidate)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(out)) != "" {
			return candidate
		}
	}
	return "51820"
}

func (m *LinuxManager) InstalledEndpointRoutes() []string {
	return append([]string(nil), m.endpointThrowRoutes...)
}

func (m *LinuxManager) RestoreEndpointRoutes(routes []string) {
	m.endpointThrowRoutes = append([]string(nil), routes...)
}

func (m *LinuxManager) removeFullTunnelRoutes(ifaceName string) error {
	tableStr := strconv.Itoa(m.table)
	if !m.tableSet {
		// In-memory state was lost (fresh process / crash recovery without
		// persisted table). Scan the actual kernel routing tables for one
		// that holds our default route on this interface, falling back to
		// the wg-quick canonical default 51820 if nothing matches.
		tableStr = m.findOwnedTable(ifaceName)
	}

	// Routes — single delete is sufficient (only one route per table).
	if err := runCmd("ip", "route", "delete", "default", "dev", ifaceName, "table", tableStr); err != nil {
		slog.Warn("failed to remove IPv4 default route", "table", tableStr, "error", err)
	}
	if err := runCmd("ip", "-6", "route", "delete", "default", "dev", ifaceName, "table", tableStr); err != nil {
		slog.Warn("failed to remove IPv6 default route", "table", tableStr, "error", err)
	}
	for _, hostCIDR := range m.endpointThrowRoutes {
		args := endpointThrowRouteDeleteArgs(hostCIDR, tableStr)
		if err := runCmd("ip", args...); err != nil {
			slog.Warn("failed to remove endpoint throw route", "route", hostCIDR, "table", tableStr, "error", err)
		}
	}
	m.endpointThrowRoutes = nil

	// Policy rules — delete by priority. Targeting our priority is precise
	// even when a previous helper crash left duplicates (each duplicate
	// occupies the same priority slot, so the delete loop drains them one
	// by one). Without priority targeting we'd risk eating rules from
	// other tools that happen to use the same table number.
	priorityMarker := func(prio string) string { return prio + ":" }
	deleteByPriority := func(proto, prio string) {
		marker := priorityMarker(prio)
		for i := 0; i < 50; i++ { // safety bound on duplicates
			out, _ := runOut("ip", proto, "rule", "show")
			if !strings.Contains(string(out), marker) {
				break
			}
			if err := runCmd("ip", proto, "rule", "delete", "priority", prio); err != nil {
				break
			}
		}
	}
	deleteByPriority("-4", wgRulePriorityFwmark)
	deleteByPriority("-6", wgRulePriorityFwmark)
	deleteByPriority("-4", wgRulePrioritySuppress)
	deleteByPriority("-6", wgRulePrioritySuppress)

	return nil
}

func endpointThrowRouteDeleteArgs(hostCIDR, tableStr string) []string {
	args := []string{"route", "delete", "throw", hostCIDR, "table", tableStr}
	if strings.Contains(hostCIDR, ":") {
		args = append([]string{"-6"}, args...)
	}
	return args
}

// resolveTableAndFwMark parses the Table and FwMark config values.
// Returns (table number, fwmark). table=-1 means "off" (skip routing).
// table=0 means use main table. Default is 51820.
func resolveTableAndFwMark(tableCfg, fwmarkCfg string) (int, int) {
	fwmark := 51820
	if fwmarkCfg != "" {
		if parsed, err := parseIntOrHex(fwmarkCfg); err == nil {
			fwmark = parsed
		} else {
			slog.Warn("invalid FwMark config, using default", "fwmark", fwmarkCfg, "error", err)
		}
	}

	table := fwmark // default: table = fwmark (wg-quick convention)
	switch strings.ToLower(strings.TrimSpace(tableCfg)) {
	case "", "auto":
		// auto: use fwmark value as table, auto-increment if in use
		table = findFreeTable(fwmark)
	case "off":
		return -1, fwmark
	default:
		if parsed, err := strconv.Atoi(tableCfg); err == nil {
			table = parsed
		} else {
			slog.Warn("invalid Table config, using auto", "table", tableCfg, "error", err)
			table = findFreeTable(fwmark)
		}
	}
	return table, fwmark
}
