//go:build linux

package network

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// dnsStateFile is persisted alongside the active tunnel state so that crash
// recovery can restore /etc/resolv.conf even if the process restarts.
const dnsStateFile = "original-dns.json"

// LinuxManager implements NetworkManager for Linux using netlink/ip commands.
type LinuxManager struct {
	origDNS []string
	// dataDir is the persistent state directory (e.g. /var/lib/wireguide).
	// If empty, DNS state persistence is skipped (graceful degradation).
	dataDir string
	// fwmark and table track the values used for full-tunnel routing so
	// RemoveRoutes can clean them up correctly.
	fwmark int
	table  int
	// tableSet distinguishes "table was explicitly set to 0 (main table)"
	// from "table was never set". Without this, removeFullTunnelRoutes
	// cannot tell whether 0 means main table or uninitialised.
	tableSet bool
}

func NewPlatformManager() NetworkManager {
	return &LinuxManager{}
}

func (m *LinuxManager) AssignAddress(ifaceName string, addresses []string) error {
	for _, addr := range addresses {
		if err := runCmd("ip", "addr", "add", addr, "dev", ifaceName); err != nil {
			return fmt.Errorf("assigning address %s: %w", addr, err)
		}
	}
	return nil
}

func (m *LinuxManager) SetMTU(ifaceName string, mtu int) error {
	if mtu <= 0 {
		// Auto-detect: upstream MTU minus 80 (wg-quick algorithm)
		defaultIf := getDefaultInterface()
		if defaultIf != "" {
			if upMTU := getInterfaceMTU(defaultIf); upMTU > 0 {
				mtu = upMTU - 80
			}
		}
		if mtu <= 0 {
			mtu = 1420
		}
		if mtu < 1280 {
			mtu = 1280
		}
	}
	return runCmd("ip", "link", "set", "dev", ifaceName, "mtu", fmt.Sprintf("%d", mtu))
}

func getDefaultInterface() string {
	out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
	if err != nil {
		return ""
	}
	// Parse "default via <gw> dev <iface> ..."
	fields := strings.Fields(strings.TrimSpace(string(out)))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func getInterfaceMTU(ifaceName string) int {
	out, err := exec.Command("ip", "link", "show", "dev", ifaceName).CombinedOutput()
	if err != nil {
		return 0
	}
	// Parse "... mtu <value> ..."
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "mtu" && i+1 < len(fields) {
			if v, err := strconv.Atoi(fields[i+1]); err == nil {
				return v
			}
		}
	}
	return 0
}

func (m *LinuxManager) BringUp(ifaceName string) error {
	return runCmd("ip", "link", "set", "dev", ifaceName, "up")
}

func (m *LinuxManager) AddRoutes(ifaceName string, allowedIPs []string, fullTunnel bool, endpointIPs []string, tableCfg string, fwmarkCfg string) error {
	// H8: Parse Table config
	table, fwmark := resolveTableAndFwMark(tableCfg, fwmarkCfg)

	// Table = off → skip routing entirely
	if table == -1 {
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
		existingOut, _ := exec.Command("ip", proto, "route", "show", "dev", ifaceName, "match", cidr).CombinedOutput()
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
		v4Out, _ := exec.Command("ip", "-4", "route", "show", "table", candidateStr).CombinedOutput()
		v6Out, _ := exec.Command("ip", "-6", "route", "show", "table", candidateStr).CombinedOutput()
		if strings.TrimSpace(string(v4Out)) == "" && strings.TrimSpace(string(v6Out)) == "" {
			return candidate
		}
	}
	return tableNum // fallback
}

func (m *LinuxManager) addFullTunnelRoutesWithConfig(ifaceName string, endpoints []string, table, fwmark int) error {
	// wg-quick-compatible fwmark-based policy routing:
	// 1. Set fwmark on WireGuard socket so its encrypted packets bypass the policy rule
	// 2. Add default route in WG routing table (both IPv4 and IPv6)
	// 3. Add policy rule: packets NOT marked -> use WG table
	// 4. Suppress main table default route for local subnet lookups

	tableStr := strconv.Itoa(table)
	fwmarkStr := strconv.Itoa(fwmark)

	m.fwmark = fwmark
	m.table = table
	m.tableSet = true

	// Step 1: Set fwmark on WireGuard socket (critical -- without this,
	// encrypted WG packets are unmarked and match the policy rule, creating
	// a routing loop that kills all connectivity).
	if err := runCmd("wg", "set", ifaceName, "fwmark", fwmarkStr); err != nil {
		return fmt.Errorf("setting fwmark on %s: %w", ifaceName, err)
	}

	// Step 2: Default routes in routing table
	if err := runCmd("ip", "route", "add", "default", "dev", ifaceName, "table", tableStr, "proto", "static"); err != nil {
		return fmt.Errorf("adding IPv4 default route to table %s: %w", tableStr, err)
	}
	// IPv6 default route (if kernel supports it -- errors are non-fatal)
	if err := runCmd("ip", "-6", "route", "add", "default", "dev", ifaceName, "table", tableStr, "proto", "static"); err != nil {
		// LOW: Log IPv6 failures at warn level instead of silently swallowing
		slog.Warn("failed to add IPv6 default route", "table", tableStr, "error", err)
	}

	// Step 3: Policy rules -- unmarked traffic uses WG table
	if err := runCmd("ip", "rule", "add", "not", "fwmark", fwmarkStr, "table", tableStr); err != nil {
		return fmt.Errorf("adding IPv4 policy rule: %w", err)
	}
	if err := runCmd("ip", "-6", "rule", "add", "not", "fwmark", fwmarkStr, "table", tableStr); err != nil {
		slog.Warn("failed to add IPv6 policy rule", "table", tableStr, "error", err)
	}

	// Step 4: Suppress main table default route for local subnet traffic
	if err := runCmd("ip", "rule", "add", "table", "main", "suppress_prefixlength", "0"); err != nil {
		slog.Warn("failed to add IPv4 suppress rule", "error", err)
	}
	if err := runCmd("ip", "-6", "rule", "add", "table", "main", "suppress_prefixlength", "0"); err != nil {
		slog.Warn("failed to add IPv6 suppress rule", "error", err)
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

	return nil
}

func (m *LinuxManager) RemoveRoutes(ifaceName string, allowedIPs []string, fullTunnel bool) error {
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
		var err error
		if tableStr != "" {
			err = runCmd("ip", "route", "delete", cidr, "dev", ifaceName, "table", tableStr)
		} else {
			err = runCmd("ip", "route", "delete", cidr, "dev", ifaceName)
		}
		if err != nil {
			slog.Warn("failed to remove route", "cidr", cidr, "iface", ifaceName, "table", tableStr, "error", err)
		}
	}
	return nil
}

// RestoreRoutingState re-populates the in-memory table/fwmark fields from
// persisted values (e.g. crash recovery state). This allows removeFullTunnelRoutes
// to use the correct values even on a fresh process.
func (m *LinuxManager) RestoreRoutingState(table, fwmark string) {
	if table != "" {
		if parsed, err := strconv.Atoi(table); err == nil {
			m.table = parsed
			m.tableSet = true
		}
	}
	if fwmark != "" {
		if parsed, err := parseIntOrHex(fwmark); err == nil {
			m.fwmark = parsed
		}
	}
}

func (m *LinuxManager) removeFullTunnelRoutes(ifaceName string) error {
	tableStr := strconv.Itoa(m.table)
	fwmarkStr := strconv.Itoa(m.fwmark)
	if !m.tableSet {
		tableStr = "51820"
		fwmarkStr = "51820"
	}

	// Routes — single delete is sufficient (only one route per table).
	if err := runCmd("ip", "route", "delete", "default", "dev", ifaceName, "table", tableStr); err != nil {
		slog.Warn("failed to remove IPv4 default route", "table", tableStr, "error", err)
	}
	if err := runCmd("ip", "-6", "route", "delete", "default", "dev", ifaceName, "table", tableStr); err != nil {
		slog.Warn("failed to remove IPv6 default route", "table", tableStr, "error", err)
	}

	// Policy rules — use while-loops matching wg-quick's del_if().
	// ip rule add can create duplicates (e.g. reconnect without clean disconnect,
	// or crash recovery), so we must delete ALL matching rules, not just one.
	lookupStr := "lookup " + tableStr
	deleteRulesWhile := func(proto string, args ...string) {
		for i := 0; i < 50; i++ { // safety bound
			out, _ := exec.Command("ip", proto, "rule", "show").CombinedOutput()
			if !strings.Contains(string(out), lookupStr) {
				break
			}
			if err := runCmd(append([]string{"ip", proto, "rule", "delete"}, args...)...); err != nil {
				break
			}
		}
	}
	deleteSuppressWhile := func(proto string) {
		marker := "from all lookup main suppress_prefixlength 0"
		for i := 0; i < 50; i++ {
			out, _ := exec.Command("ip", proto, "rule", "show").CombinedOutput()
			if !strings.Contains(string(out), marker) {
				break
			}
			if err := runCmd("ip", proto, "rule", "delete", "table", "main", "suppress_prefixlength", "0"); err != nil {
				break
			}
		}
	}

	deleteRulesWhile("-4", "table", tableStr)
	deleteRulesWhile("-6", "table", tableStr)
	deleteSuppressWhile("-4")
	deleteSuppressWhile("-6")

	return nil
}

func (m *LinuxManager) SetDNS(ifaceName string, servers []string) error {
	if len(servers) == 0 {
		return nil
	}

	// Separate DNS IPs from search domains (H9)
	var dnsIPs, searchDomains []string
	for _, s := range servers {
		if net.ParseIP(s) != nil {
			dnsIPs = append(dnsIPs, s)
		} else {
			// Treat non-IP entries as search domains
			searchDomains = append(searchDomains, s)
		}
	}

	// Try systemd-resolved first
	if tryResolvectl(ifaceName, dnsIPs, searchDomains) {
		return nil
	}

	// H9: Fallback to resolvconf if available
	if tryResolvconf(ifaceName, dnsIPs, searchDomains) {
		return nil
	}

	// Final fallback: rewrite /etc/resolv.conf directly. NEVER use `sh -c "echo ..."`
	// here -- server strings are attacker-influenced and would allow shell
	// injection. Use os.WriteFile with atomic rename.

	// M7: Check if /etc/resolv.conf is a symlink. If so, refuse to overwrite
	// and warn the user.
	if isSymlink("/etc/resolv.conf") {
		slog.Warn("/etc/resolv.conf is a symlink, refusing to overwrite directly; DNS may not work as expected. Install resolvconf or systemd-resolved.")
		return fmt.Errorf("/etc/resolv.conf is a symlink; install resolvectl or resolvconf for DNS management")
	}

	origData, _ := os.ReadFile("/etc/resolv.conf")
	m.origDNS = strings.Split(strings.TrimSpace(string(origData)), "\n")

	// M8: Persist original DNS to disk for crash recovery
	m.persistOrigDNS()

	var lines []string
	for _, s := range dnsIPs {
		lines = append(lines, "nameserver "+s)
	}
	// H9: Include search domains
	if len(searchDomains) > 0 {
		lines = append(lines, "search "+strings.Join(searchDomains, " "))
	}
	content := strings.Join(lines, "\n") + "\n"
	return writeResolvConf(content)
}

// tryResolvectl attempts to set DNS via systemd-resolved. Returns true on success.
func tryResolvectl(ifaceName string, dnsIPs, searchDomains []string) bool {
	if len(dnsIPs) == 0 {
		return false
	}
	args := []string{"dns", ifaceName}
	args = append(args, dnsIPs...)
	if err := runCmd("resolvectl", args...); err != nil {
		return false
	}
	// Set catch-all routing domain so systemd-resolved actually sends
	// queries to our DNS servers.
	domains := []string{"~."}
	domains = append(domains, searchDomains...)
	_ = runCmd("resolvectl", append([]string{"domain", ifaceName}, domains...)...)
	return true
}

// resolvconfIfacePrefix returns the interface prefix from /etc/resolvconf/interface-order,
// matching wg-quick's resolvconf_iface_prefix(). This controls DNS priority ordering
// on Debian/Ubuntu systems with openresolv. Returns empty string if not applicable.
func resolvconfIfacePrefix() string {
	path, err := exec.LookPath("resolvconf")
	if err != nil || path == "" {
		return ""
	}
	// Only apply prefix for real openresolv, not systemd-resolved's shim (a symlink).
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 {
		return ""
	}
	data, err := os.ReadFile("/etc/resolvconf/interface-order")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(line, "*") {
			prefix := strings.TrimSuffix(line, "*")
			if len(prefix) > 0 {
				return prefix + "."
			}
		}
	}
	return ""
}

// tryResolvconf attempts to set DNS via the resolvconf utility (H9).
// Returns true on success.
func tryResolvconf(ifaceName string, dnsIPs, searchDomains []string) bool {
	path, err := exec.LookPath("resolvconf")
	if err != nil || path == "" {
		return false
	}

	var input strings.Builder
	for _, ip := range dnsIPs {
		fmt.Fprintf(&input, "nameserver %s\n", ip)
	}
	if len(searchDomains) > 0 {
		fmt.Fprintf(&input, "search %s\n", strings.Join(searchDomains, " "))
	}

	prefixedName := resolvconfIfacePrefix() + ifaceName
	cmd := exec.Command("resolvconf", "-a", prefixedName, "-m", "0", "-x")
	cmd.Stdin = strings.NewReader(input.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		slog.Warn("resolvconf failed", "error", err, "output", strings.TrimSpace(string(out)))
		return false
	}
	return true
}

// isSymlink returns true if the given path is a symbolic link (M7).
func isSymlink(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSymlink != 0
}

// persistOrigDNS saves original DNS state to disk (M8).
func (m *LinuxManager) persistOrigDNS() {
	if m.dataDir == "" {
		return
	}
	data, err := json.Marshal(m.origDNS)
	if err != nil {
		slog.Warn("failed to marshal original DNS state", "error", err)
		return
	}
	path := filepath.Join(m.dataDir, dnsStateFile)
	if err := os.WriteFile(path, data, 0600); err != nil {
		slog.Warn("failed to persist original DNS state", "error", err)
	}
}

// loadPersistedDNS reads original DNS state from disk (M8).
func (m *LinuxManager) loadPersistedDNS() []string {
	if m.dataDir == "" {
		return nil
	}
	path := filepath.Join(m.dataDir, dnsStateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var dns []string
	if err := json.Unmarshal(data, &dns); err != nil {
		slog.Warn("failed to parse persisted DNS state", "error", err)
		return nil
	}
	return dns
}

// clearPersistedDNS removes the persisted DNS state file.
func (m *LinuxManager) clearPersistedDNS() {
	if m.dataDir == "" {
		return
	}
	path := filepath.Join(m.dataDir, dnsStateFile)
	_ = os.Remove(path)
}

// ResetDNSToSystemDefault clears DNS overrides without relying on in-memory
// state. Used by crash recovery. On Linux with systemd-resolved this reverts
// the interface; on the resolv.conf fallback path it restores from persisted
// state (M8).
func (m *LinuxManager) ResetDNSToSystemDefault() error {
	// Try reverting all WireGuard-like interfaces. `resolvectl revert`
	// expects an actual link name, not the literal "default".
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if strings.HasPrefix(iface.Name, "wg") || strings.HasPrefix(iface.Name, "utun") {
			_ = runCmd("resolvectl", "revert", iface.Name)
			// H9: Also try removing via resolvconf (with prefix)
			if path, err := exec.LookPath("resolvconf"); err == nil && path != "" {
				prefixedName := resolvconfIfacePrefix() + iface.Name
				_ = runCmd("resolvconf", "-d", prefixedName, "-f")
			}
		}
	}

	// M8: Try restoring from persisted DNS state
	if persisted := m.loadPersistedDNS(); len(persisted) > 0 {
		content := strings.Join(persisted, "\n") + "\n"
		if !isSymlink("/etc/resolv.conf") {
			if err := writeResolvConf(content); err != nil {
				slog.Warn("failed to restore persisted DNS state", "error", err)
			}
		}
		m.clearPersistedDNS()
	}

	return nil
}

func (m *LinuxManager) RestoreDNS(ifaceName string) error {
	// H9: Try resolvconf cleanup first, using the same prefixed name
	if path, err := exec.LookPath("resolvconf"); err == nil && path != "" {
		prefixedName := resolvconfIfacePrefix() + ifaceName
		_ = runCmd("resolvconf", "-d", prefixedName, "-f")
	}

	// Try resolvectl revert
	_ = runCmd("resolvectl", "revert", ifaceName)

	// Restore from in-memory state
	if len(m.origDNS) == 0 {
		// M8: Try loading from persisted state
		m.origDNS = m.loadPersistedDNS()
	}
	if len(m.origDNS) == 0 {
		return nil
	}
	content := strings.Join(m.origDNS, "\n") + "\n"
	if !isSymlink("/etc/resolv.conf") {
		if err := writeResolvConf(content); err != nil {
			return err
		}
	}
	m.clearPersistedDNS()
	return nil
}

// writeResolvConf atomically rewrites /etc/resolv.conf. Used only as a fallback
// when resolvectl and resolvconf are unavailable.
// M7: Caller must check isSymlink() before calling this.
func writeResolvConf(content string) error {
	tmp := "/etc/resolv.conf.wireguide.tmp"
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, "/etc/resolv.conf"); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// H10: Cleanup now removes policy rules, routing table entries, and nftables
// rules in addition to the interface itself.
func (m *LinuxManager) Cleanup(ifaceName string) error {
	_ = m.RestoreDNS(ifaceName)

	// H10: Remove routes and policy rules (crash recovery path)
	// Try removing full-tunnel routes with both stored and default values.
	m.removeFullTunnelRoutes(ifaceName)

	// H10: Clean up nftables rules that may have been left by the firewall.
	// This is best-effort -- the firewall's own Cleanup should handle this,
	// but in crash recovery the firewall object may not have state.
	if out, err := exec.Command("nft", "delete", "table", "inet", "wireguide").CombinedOutput(); err != nil {
		slog.Warn("cleanup: nft delete wireguide table", "error", err, "output", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("nft", "delete", "table", "inet", "wireguide_dns").CombinedOutput(); err != nil {
		slog.Warn("cleanup: nft delete wireguide_dns table", "error", err, "output", strings.TrimSpace(string(out)))
	}

	// Delete the interface
	if err := runCmd("ip", "link", "delete", "dev", ifaceName); err != nil {
		slog.Warn("cleanup: failed to delete interface", "iface", ifaceName, "error", err)
	}
	return nil
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
