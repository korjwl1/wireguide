//go:build darwin

package network

import (
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

// AddRoutes installs routes for AllowedIPs. For /0 (full tunnel) it uses
// the split-route trick + endpoint bypass. Routes are added longest-prefix
// first to avoid transient conflicts (wg-quick's sort -nr -k 2 -t /).
func (m *DarwinManager) AddRoutes(ifaceName string, allowedIPs []string, fullTunnel bool, endpoints []string, tableCfg string, fwmarkCfg string) error {
	if strings.EqualFold(tableCfg, "off") {
		slog.Info("Table=off: skipping route installation", "interface", ifaceName)
		return nil
	}
	// Sort by prefix length descending (longest first)
	sorted := sortAllowedIPs(allowedIPs)

	hasV4Default := false
	hasV6Default := false
	for _, cidr := range sorted {
		isV6 := strings.Contains(cidr, ":")
		if cidr == "0.0.0.0/0" {
			hasV4Default = true
			continue
		}
		if cidr == "::/0" {
			hasV6Default = true
			continue
		}
		// Non-default route: skip if already pointing at this interface (idempotent)
		family := "-inet"
		if isV6 {
			family = "-inet6"
		}
		if existing, _ := runOut("route", "-n", "get", family, cidr); routeUsesInterface(existing, ifaceName) {
			continue
		}
		if err := run("route", "-q", "-n", "add", family, cidr, "-interface", ifaceName); err != nil {
			return fmt.Errorf("adding route %s: %w", cidr, err)
		}
	}

	// Cache the upstream interface BEFORE installing split routes — after
	// split routes, route-get would return utun instead of the physical iface.
	// Only when pinInterface is enabled (dual-network stability).
	m.mu.Lock()
	pin := m.pinInterface
	m.mu.Unlock()
	if pin {
		upstreamIface := getDefaultInterface()
		m.mu.Lock()
		m.lastUpstreamIface = upstreamIface
		m.mu.Unlock()
	}

	// CORRECTNESS — bypass /32 host routes go in BEFORE the /1 split routes.
	// Reason: wireguard-go on darwin has no SO_MARK / IP_BOUND_IF socket
	// binding (conn/mark_default.go is a no-op on Darwin), so the kernel's
	// routing decision for the encrypted UDP send is purely longest-prefix-
	// match. If /1 lands first, there is a window between /1-install and
	// /32-install where the WG handshake retransmits (already firing because
	// connect_phases.engine.Start() ran before AddRoutes) match /1 → re-enter
	// utun → loop. This is the exact bug class issue #14 fixed on Windows;
	// macOS carries the same risk.
	//
	// `endpoints` here are ALREADY-RESOLVED IP LITERALS — the caller
	// (connect_phases) resolved them via the wireguard-go engine at a
	// moment where the tunnel routes were not yet in place. We must never
	// DNS-resolve here, because by this point the /1 split routes below
	// would route the DNS query back through utun, creating a loop.
	//
	// Cache the upstream gateway per family once — one netstat call per
	// family instead of one per endpoint IP. Bounded poll (5 s @ 250 ms)
	// rides out sleep/wake, Wi-Fi handoff, and slow DHCP — matches the
	// Windows underlay-detection retry.
	var gwV4, gwV6 string
	var gwV4Err, gwV6Err error
	const underlayPollInterval = 250 * time.Millisecond
	const underlayPollBudget = 5 * time.Second
	pollDeadline := time.Now().Add(underlayPollBudget)
	for {
		if hasV4Default {
			gwV4, gwV4Err = getDefaultGatewayFor(false)
		}
		if hasV6Default {
			gwV6, gwV6Err = getDefaultGatewayFor(true)
		}
		needV4 := hasV4Default && (gwV4Err != nil || gwV4 == "")
		needV6 := hasV6Default && (gwV6Err != nil || gwV6 == "")
		if !needV4 && !needV6 {
			break
		}
		if time.Now().After(pollDeadline) {
			break
		}
		time.Sleep(underlayPollInterval)
	}

	// Classify endpoints by family BEFORE we touch the route table so we
	// can refuse a connect whose family lacks a usable underlay rather than
	// silently installing /1 against a missing gateway.
	type epClassified struct {
		raw  string
		isV6 bool
	}
	var classified []epClassified
	haveV4Endpoints := false
	haveV6Endpoints := false
	for _, ipStr := range endpoints {
		if ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			slog.Warn("skipping invalid endpoint IP", "ip", ipStr)
			continue
		}
		isV6 := ip.To4() == nil
		if isV6 && !hasV6Default {
			continue
		}
		if !isV6 && !hasV4Default {
			continue
		}
		classified = append(classified, epClassified{raw: ipStr, isV6: isV6})
		if isV6 {
			haveV6Endpoints = true
		} else {
			haveV4Endpoints = true
		}
	}
	if haveV4Endpoints && (gwV4Err != nil || gwV4 == "") {
		return fmt.Errorf("full-tunnel: cannot detect a usable IPv4 default gateway "+
			"(err=%v). Refusing to install split routes — without an endpoint bypass "+
			"the encrypted WireGuard traffic would loop through the tunnel and "+
			"saturate the link", gwV4Err)
	}
	if haveV6Endpoints && (gwV6Err != nil || gwV6 == "") {
		return fmt.Errorf("full-tunnel: cannot detect a usable IPv6 default gateway "+
			"(err=%v). IPv6 peer endpoint cannot be bypassed safely", gwV6Err)
	}

	// PHASE 1: bypass host routes for every classified endpoint. Fail-fast:
	// any install failure aborts the connect and the caller's rollback
	// removes anything we managed to install. The previous best-effort
	// path silently dropped failures (one slog.Warn per IP) and left the
	// connect to proceed into the /1 install with broken bypass — the
	// path that produces the 6 GB-upload loop class.
	for _, ep := range classified {
		if err := m.addBypassForIP(ep.raw, gwV4, gwV6, gwV4Err, gwV6Err); err != nil {
			return fmt.Errorf("endpoint bypass %s: %w", ep.raw, err)
		}
	}

	// PHASE 2: /1 split-route trick. Now safe to install — every endpoint
	// matched by 0.0.0.0/1 or 128.0.0.0/1 already has a longest-prefix /32
	// pointing at the physical gateway.
	if hasV4Default {
		if err := run("route", "-q", "-n", "add", "-inet", "0.0.0.0/1", "-interface", ifaceName); err != nil {
			return fmt.Errorf("adding 0.0.0.0/1: %w", err)
		}
		if err := run("route", "-q", "-n", "add", "-inet", "128.0.0.0/1", "-interface", ifaceName); err != nil {
			return fmt.Errorf("adding 128.0.0.0/1: %w", err)
		}
	}
	if hasV6Default {
		if err := run("route", "-q", "-n", "add", "-inet6", "::/1", "-interface", ifaceName); err != nil {
			return fmt.Errorf("adding ::/1: %w", err)
		}
		if err := run("route", "-q", "-n", "add", "-inet6", "8000::/1", "-interface", ifaceName); err != nil {
			return fmt.Errorf("adding 8000::/1: %w", err)
		}
	}

	// Snapshot the current upstream gateway so reapply() can detect genuine
	// changes (Wi-Fi switch etc.) and ignore spurious RTM events.
	currentV4, _ := getDefaultGatewayFor(false)
	currentV6, _ := getDefaultGatewayFor(true)

	// Stash context for reapply on network changes.
	m.mu.Lock()
	m.lastIface = ifaceName
	m.lastEndpoints = append([]string(nil), endpoints...)
	m.lastHasV4Default = hasV4Default
	m.lastHasV6Default = hasV6Default
	m.lastGatewayV4 = currentV4
	m.lastGatewayV6 = currentV6
	m.mu.Unlock()

	// Start route monitor for full-tunnel mode. Without this, switching Wi-Fi
	// networks would leave the endpoint bypass route pointing at the stale
	// gateway and break the tunnel (wg-quick handles this via monitor_daemon).
	//
	// Start is delayed by 2 seconds so that the RTM_* events emitted by our
	// own `route add` commands above (and any OS-driven chatter immediately
	// after the interface comes up) don't trigger a spurious reapply in the
	// critical handshake window. reapply() itself also gates on
	// lastGatewayV4/V6 changes, so this delay is belt-and-suspenders — but
	// cheap insurance against a class of timing bugs.
	// M4: Start route monitor not only for full-tunnel, but also when DNS is
	// configured or endpoints exist in split-tunnel mode. DNS can be disrupted
	// by network changes even in split-tunnel mode, and endpoint bypass routes
	// (if any) need the same gateway-change tracking.
	needsMonitor := fullTunnel || len(m.lastDNS) > 0
	if needsMonitor {
		// Subscribe under the interface name. The process-wide rmMgr
		// owns the single `route -n monitor` subprocess shared across
		// all connected tunnels. First Subscribe spawns it (delayed
		// 2 s), last Unsubscribe stops it.
		m.mu.Lock()
		m.monitorKey = ifaceName
		m.mu.Unlock()
		rmMgr.Subscribe(ifaceName, m.reapply)
	}

	return nil
}

// installBlackholeBypass installs a /32 (or /128) route to the given
// peer endpoint IP pointing at loopback with -blackhole. Used as a
// loop-firewall in the reapply (network-change) path when the upstream
// gateway probe fails — the alternative is leaving the /1 split route
// in force without a /32 bypass, which loops encrypted UDP through
// utun. Records the IP in m.bypassEndpoints so RemoveRoutes /
// disconnect can sweep it. If installation fails, reapply keeps outer
// sends blocked and the route watchdog reports the unsafe endpoint.
func (m *DarwinManager) installBlackholeBypass(ipStr string, isV6 bool) {
	if existing, err := lookupEndpointRoute(ipStr); err == nil && existing.blocksTraffic() {
		m.recordBypass(ipStr)
		return // don't generate new route events for an unchanged safe outage
	}
	family := "-inet"
	loopback := "127.0.0.1"
	if isV6 {
		family = "-inet6"
		loopback = "::1"
	}
	if err := run("route", "-q", "-n", "add", family, ipStr, loopback, "-blackhole"); err != nil {
		// RTM_CHANGE cannot change BLACKHOLE/REJECT flags on Darwin.
		// reapply has paused outer sends before this replacement.
		_ = run("route", "-q", "-n", "delete", family, ipStr)
		if addErr := run("route", "-q", "-n", "add", family, ipStr, loopback, "-blackhole"); addErr != nil {
			slog.Error("blackhole bypass install failed", "ip", ipStr, "error", addErr)
			return
		}
	}
	m.recordBypass(ipStr)
}

func (m *DarwinManager) recordBypass(ipStr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.bypassEndpoints {
		if existing == ipStr {
			return
		}
	}
	m.bypassEndpoints = append(m.bypassEndpoints, ipStr)
}

// addBypassForIP installs a host route for one already-resolved peer endpoint
// IP, pointing at the upstream default gateway. Without this, encrypted WG
// packets destined for the peer would match the /1 split routes and loop
// back through the tunnel itself.
//
// Gateways are passed in (not resolved here) so the caller can make a single
// netstat call for all IPs in a batch — one per family instead of one per IP.
//
// If the gateway probe failed for a given family this returns an error and
// the caller MUST refuse the connect (the rollback path will sweep any
// half-installed state). The previous blackhole-and-continue fallback was
// silently-permissive: it broke the loop class only by also breaking the
// tunnel, with no surfaced signal that anything was wrong.
func (m *DarwinManager) addBypassForIP(ipStr, gwV4, gwV6 string, gwV4Err, gwV6Err error) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid endpoint IP %q", ipStr)
	}
	isV6 := ip.To4() == nil

	var gw string
	var gwErr error
	family := "-inet"
	if isV6 {
		gw = gwV6
		gwErr = gwV6Err
		family = "-inet6"
	} else {
		gw = gwV4
		gwErr = gwV4Err
	}

	if gwErr != nil || gw == "" {
		return fmt.Errorf("no usable upstream gateway for %s (family=%s, err=%v)", ipStr, family, gwErr)
	}
	// A blackhole's flags survive RTM_CHANGE. Replace it with sends
	// paused, rather than leaving the tunnel permanently blackholed.
	if existing, err := lookupEndpointRoute(ipStr); err == nil && existing.blocksTraffic() {
		if err := run("route", "-q", "-n", "delete", family, ipStr); err != nil {
			return fmt.Errorf("remove blocked endpoint route %s: %w", ipStr, err)
		}
	}

	// Use the cached upstream interface to pin the bypass route with
	// -ifscope. This prevents macOS from flapping between WiFi and
	// Ethernet when both are active.
	m.mu.Lock()
	iface := m.lastUpstreamIface
	m.mu.Unlock()

	// Try `route add` first, fall back to `route change` if the kernel
	// already has a route for this host (common when reconnecting).
	if iface != "" {
		if err := run("route", "-q", "-n", "add", family, ipStr, "-gateway", gw, "-ifscope", iface); err != nil {
			if err2 := run("route", "-q", "-n", "change", family, ipStr, "-gateway", gw, "-ifscope", iface); err2 != nil {
				// Fallback: try without -ifscope in case the OS rejects it
				slog.Debug("ifscope route failed, falling back to unscoped", "ip", ipStr, "iface", iface)
				if err3 := run("route", "-q", "-n", "add", family, ipStr, "-gateway", gw); err3 != nil {
					if err4 := run("route", "-q", "-n", "change", family, ipStr, "-gateway", gw); err4 != nil {
						return fmt.Errorf("bypass route %s via %s (ifscope %s failed, unscoped also failed): %v", ipStr, gw, iface, err4)
					}
				}
			}
		}
	} else {
		if err := run("route", "-q", "-n", "add", family, ipStr, "-gateway", gw); err != nil {
			if err2 := run("route", "-q", "-n", "change", family, ipStr, "-gateway", gw); err2 != nil {
				return fmt.Errorf("bypass route %s via %s: add=%v, change=%v", ipStr, gw, err, err2)
			}
		}
	}
	m.recordBypass(ipStr)
	return nil
}

// RemoveRoutes cleans up. wg-quick approach: walk netstat and remove ALL
// routes pointing at this interface, then remove endpoint bypass routes.
// This is more robust than tracking what we added.
func (m *DarwinManager) RemoveRoutes(ifaceName string, allowedIPs []string, fullTunnel bool) error {
	// Unsubscribe from the process-wide route monitor first so a
	// concurrent fanOut() can't deliver another reapply() against the
	// tunnel we're about to tear down. Unsubscribe() blocks until any
	// in-flight reapply() that touches this manager finishes when this
	// is the last subscriber (rmMgr.Stop() → pending.Wait()).
	m.mu.Lock()
	key := m.monitorKey
	m.monitorKey = ""
	m.mu.Unlock()
	if key != "" {
		rmMgr.Unsubscribe(key)
	}
	m.routeMu.Lock()
	defer m.routeMu.Unlock()

	// Remove all routes via this interface (both IPv4 and IPv6)
	m.deleteInterfaceRoutes(ifaceName, "inet")
	m.deleteInterfaceRoutes(ifaceName, "inet6")

	// Snapshot bypass list under the lock, then delete outside.
	// Also clear lastDNS / lastMTU here so a delayed reapply
	// callback that the monitor.Stop() above couldn't preempt
	// (e.g. callback was past its mu.Unlock() but before its
	// applyDNS call) doesn't re-write the now-defunct DNS overrides
	// on every networksetup service.
	m.mu.Lock()
	bypass := m.bypassEndpoints
	m.bypassEndpoints = nil
	m.lastIface = ""
	m.lastEndpoints = nil
	m.lastGatewayV4 = ""
	m.lastGatewayV6 = ""
	m.lastHasV4Default = false
	m.lastHasV6Default = false
	m.lastDNS = nil
	m.lastMTU = 0
	m.mu.Unlock()

	for _, ip := range bypass {
		family := "-inet"
		if strings.Contains(ip, ":") {
			family = "-inet6"
		}
		if err := run("route", "-q", "-n", "delete", family, ip); err != nil {
			slog.Debug("bypass route delete failed (may already be gone)", "ip", ip, "error", err)
		}
	}
	return nil
}

// deleteInterfaceRoutes walks netstat for the given family and deletes
// every route whose interface (Netif column) matches ifaceName.
// Also handles the wg-quick IPv6 edge case where Netif=lo0 but Gateway=utunN.
func (m *DarwinManager) deleteInterfaceRoutes(ifaceName, family string) {
	out, err := runOut("netstat", "-nr", "-f", family)
	if err != nil {
		return
	}
	// Parse header to find Destination / Gateway / Netif column positions.
	netifIdx, destIdx, gwIdx := -1, -1, -1
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if netifIdx < 0 {
			// Look for header row
			for i, f := range fields {
				switch f {
				case "Destination":
					destIdx = i
				case "Gateway":
					gwIdx = i
				case "Netif":
					netifIdx = i
				}
			}
			continue
		}
		// Require ALL three columns to be in range before indexing, not just
		// Netif — a malformed header could leave destIdx or gwIdx pointing
		// past the line and crash on field access.
		maxIdx := netifIdx
		if destIdx > maxIdx {
			maxIdx = destIdx
		}
		if gwIdx > maxIdx {
			maxIdx = gwIdx
		}
		if len(fields) <= maxIdx || destIdx < 0 || gwIdx < 0 {
			continue
		}
		dest := fields[destIdx]
		gw := fields[gwIdx]
		netif := fields[netifIdx]

		// Match: Netif is our interface, OR (IPv6 only) Netif is lo* and Gateway is our interface
		match := netif == ifaceName
		if !match && family == "inet6" && strings.HasPrefix(netif, "lo") && gw == ifaceName {
			match = true
		}
		if !match {
			continue
		}

		// Use "default" directly in route delete — macOS `route` understands
		// the keyword and it avoids ambiguity with explicit CIDR notation.
		// No translation needed.
		famFlag := "-inet"
		if family == "inet6" {
			famFlag = "-inet6"
		}
		if err := run("route", "-q", "-n", "delete", famFlag, dest); err != nil {
			slog.Debug("orphan route delete failed (may already be gone)", "family", family, "dest", dest, "error", err)
		}
	}
}

// routeUsesInterface checks `route get` output for an exact match on the
// interface field. Prevents false matches between utun3 / utun33.
func routeUsesInterface(routeOutput []byte, ifaceName string) bool {
	for _, line := range strings.Split(string(routeOutput), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
			return name == ifaceName
		}
	}
	return false
}

// getDefaultGatewayFor returns the IPv4 or IPv6 default gateway, skipping
// link-local entries (link#N) per wg-quick's collect_gateways.
var getDefaultGatewayFor = func(ipv6 bool) (string, error) {
	family := "inet"
	if ipv6 {
		family = "inet6"
	}
	out, err := runOut("netstat", "-nr", "-f", family)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] != "default" {
			continue
		}
		gw := fields[1]
		// Skip link-local defaults (point-to-point with no gateway IP)
		if strings.HasPrefix(gw, "link#") {
			continue
		}
		return gw, nil
	}
	return "", fmt.Errorf("no default gateway for %s", family)
}

// getDefaultInterface returns the name of the default route's interface
// by parsing the netstat header to locate the Netif column, then scanning
// for the `default` row. Dynamic header parsing handles column-order
// differences across macOS versions; the previous "first lowercase field"
// heuristic returned `awdl0` (AirDrop) instead of `en0` on some machines.
func getDefaultInterface() string {
	out, err := runOut("netstat", "-nr", "-f", "inet")
	if err != nil {
		return ""
	}
	netifIdx, destIdx := -1, -1
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if netifIdx < 0 {
			for i, f := range fields {
				switch f {
				case "Destination":
					destIdx = i
				case "Netif":
					netifIdx = i
				}
			}
			continue
		}
		maxIdx := netifIdx
		if destIdx > maxIdx {
			maxIdx = destIdx
		}
		if destIdx < 0 || netifIdx < 0 || len(fields) <= maxIdx {
			continue
		}
		if fields[destIdx] == "default" {
			return fields[netifIdx]
		}
	}
	return ""
}

// sortAllowedIPs sorts CIDRs by prefix length descending (longest first),
// matching wg-quick's `sort -nr -k 2 -t /`. Stable order for determinism.
func sortAllowedIPs(cidrs []string) []string {
	result := make([]string, len(cidrs))
	copy(result, cidrs)

	slices.SortStableFunc(result, func(a, b string) int {
		return prefixLen(b) - prefixLen(a)
	})
	return result
}

func prefixLen(cidr string) int {
	idx := strings.Index(cidr, "/")
	if idx < 0 {
		// Bare address without prefix — return 32 for IPv4, 128 for IPv6
		if strings.Contains(cidr, ":") {
			return 128
		}
		return 32
	}
	n, _ := strconv.Atoi(cidr[idx+1:]) // CIDRs are validated before route installation.
	return n
}
