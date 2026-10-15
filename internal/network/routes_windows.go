//go:build windows

package network

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"
)

func (m *WindowsManager) AddRoutes(ifaceName string, allowedIPs []string, fullTunnel bool, endpoints []string, tableCfg string, fwmarkCfg string) error {
	if strings.EqualFold(tableCfg, "off") {
		slog.Info("Table=off: skipping route installation", "interface", ifaceName)
		return nil
	}
	if fullTunnel {
		return m.addFullTunnelRoutes(ifaceName, endpoints)
	}
	// M14: Track split-tunnel routes so Cleanup can remove them.
	for _, cidr := range allowedIPs {
		if strings.Contains(cidr, ":") {
			if err := runWin("netsh", "interface", "ipv6", "add", "route", cidr, ifaceName, "nexthop=::"); err != nil {
				return fmt.Errorf("adding route %s: %w", cidr, err)
			}
		} else {
			if err := runWin("netsh", "interface", "ip", "add", "route", cidr, ifaceName, "nexthop=0.0.0.0"); err != nil {
				return fmt.Errorf("adding route %s: %w", cidr, err)
			}
		}
		m.splitRoutes = append(m.splitRoutes, cidr)
	}
	return nil
}

func (m *WindowsManager) addFullTunnelRoutes(ifaceName string, endpoints []string) error {
	// PREFLIGHT — fail FAST on the conditions that would otherwise produce
	// the routing-loop class of bug (issue #14 / "6 GB upload spike"):
	//
	//   - No IPv4 default route detected. Without one we cannot install the
	//     /32 bypass that keeps WireGuard's own UDP traffic off the tunnel.
	//     Continuing to install /1 split routes would silently trap the
	//     encrypted handshake inside the tunnel and recurse at line rate.
	//
	//   - No IPv4 endpoints to bypass. A full-tunnel config with zero
	//     resolved IPv4 endpoints is either malformed or pure-IPv6; the
	//     latter is handled by the IPv6 branch below. For IPv4 we refuse
	//     rather than silently leave a hole.
	//
	// Errors here propagate to connectPhases which runs `rollback` — the
	// caller never sees a partially-installed split route. No netsh-warn-
	// and-continue fallback path: the user-visible failure mode of "Connect
	// returned an error" is strictly better than "Connect succeeded and
	// your upload meter spins to 6 GB".
	// Underlay detection with bounded retry. The user-facing failure
	// mode we're guarding against is "Connect right after wake from
	// sleep / fresh boot fails because Windows hasn't installed the
	// default route yet" — typical lag is 0.5–3 s on Wi-Fi handoff,
	// up to 10 s on slow DHCP / cellular tether. 5 s is the sweet
	// spot: covers most legitimate slow-start scenarios while
	// bounding the fail-fast window to something the user perceives
	// as a normal connect delay.
	//
	// Captures: IPv4/IPv6 default-route gateway, the underlay LUID
	// (what CreateIpForwardEntry2 wants for the bypass /32), the
	// underlay ifIndex, and the IPv6 ifIndex (used for netsh-style
	// legacy paths in Cleanup). Excludes our own wintun adapter so a
	// second-connect re-detect doesn't loop on the just-up tunnel.
	var (
		origGw      string
		origGw6     string
		origIfIdx6  string
		physLuidV4  uint64
		physIfIdxV4 uint32
		physLuidV6  uint64
	)
	const underlayPollInterval = 250 * time.Millisecond
	const underlayPollBudget = 5 * time.Second
	pollDeadline := time.Now().Add(underlayPollBudget)
	for {
		origGw = getWindowsDefaultGateway()
		origGw6 = getWindowsDefaultIPv6Gateway()
		origIfIdx6 = getWindowsDefaultIPv6InterfaceIndex()
		physLuidV4, physIfIdxV4, _ = DefaultRouteV4LuidAndIndex([]string{ifaceName})
		physLuidV6, _, _ = DefaultRouteV6LuidAndIndex([]string{ifaceName})
		// We have what we need as soon as the IPv4 underlay is present;
		// IPv6 is optional and best-effort. Most VPN configs are v4-only
		// peers, so v6 underlay missing must not block.
		if origGw != "" && physLuidV4 != 0 {
			break
		}
		if time.Now().After(pollDeadline) {
			break
		}
		time.Sleep(underlayPollInterval)
	}

	// Classify endpoints by family so we can demand a usable underlay only
	// for the families we actually need to bypass.
	var v4Endpoints, v6Endpoints []net.IP
	for _, ipStr := range endpoints {
		if ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4Endpoints = append(v4Endpoints, ip.To4())
		} else {
			v6Endpoints = append(v6Endpoints, ip)
		}
	}

	// A family whose underlay (default gateway + physical LUID) is missing
	// cannot carry WireGuard's own encrypted traffic anyway, so an
	// endpoint in that family can't loop — drop it from the bypass set
	// rather than failing the whole connect. The common case is an
	// endpoint hostname that resolves to BOTH A and AAAA while the host
	// is on a v4-only network: WireGuard uses the reachable v4 endpoint,
	// and the un-bypassable v6 address is unreachable and harmless.
	usableV4 := origGw != "" && physLuidV4 != 0
	usableV6 := origGw6 != "" && physLuidV6 != 0
	if len(v4Endpoints) > 0 && !usableV4 {
		if !usableV6 {
			return fmt.Errorf("full-tunnel: cannot detect a usable IPv4 default gateway "+
				"(gw=%q, physLuid=%d) and no usable IPv6 underlay either. Refusing to "+
				"install split routes — without an endpoint bypass the encrypted "+
				"WireGuard traffic would loop through the tunnel and saturate the link",
				origGw, physLuidV4)
		}
		slog.Warn("full-tunnel: no usable IPv4 underlay; skipping IPv4 endpoint bypass (v6 underlay will carry the tunnel)",
			"v4_endpoints", len(v4Endpoints))
		v4Endpoints = nil
	}
	if len(v6Endpoints) > 0 && !usableV6 {
		if !usableV4 {
			return fmt.Errorf("full-tunnel: cannot detect a usable IPv6 default gateway "+
				"(gw=%q, physLuid=%d) and no usable IPv4 underlay either. IPv6 peer "+
				"endpoint cannot be bypassed safely",
				origGw6, physLuidV6)
		}
		slog.Warn("full-tunnel: no usable IPv6 underlay; skipping IPv6 endpoint bypass (v4 underlay will carry the tunnel)",
			"v6_endpoints", len(v6Endpoints))
		v6Endpoints = nil
	}

	// Resolve the tunnel adapter's LUID once — we'll use it for both the
	// (later) /1 split routes and any IPv6 bypass tracking.
	tunnelLuid, _ := convertInterfaceAliasToLuid(ifaceName)
	if tunnelLuid == 0 {
		return fmt.Errorf("full-tunnel: cannot resolve tunnel adapter LUID for %q", ifaceName)
	}

	gwIPv4 := net.ParseIP(origGw)

	// PHASE 1+2: bypass host routes for every IPv4 + IPv6 peer endpoint.
	// We install every row first, then batch-verify against ONE
	// snapshot of the route table per family. The naive per-route
	// VerifyIpForwardRoute would issue N GetIpForwardTable2 calls
	// for N peers — wasteful on multi-peer site-to-site configs and
	// on machines with hundreds of unrelated routes. One snapshot
	// per family is enough because Add and Verify both run while
	// addFullTunnelRoutes holds the only writer; the table can only
	// be larger at Verify time than at Add time.
	gwIPv6 := net.ParseIP(origGw6)
	wantKeys := make([]routeKey, 0, len(v4Endpoints)+len(v6Endpoints))
	for _, ip := range v4Endpoints {
		err := AddIpForwardRoute(physLuidV4, physIfIdxV4, ip, 32, gwIPv4, 1)
		if err != nil && !errors.Is(err, ErrRouteAlreadyExists) {
			return fmt.Errorf("installing IPv4 endpoint bypass %s via %s: %w", ip, origGw, err)
		}
		wantKeys = append(wantKeys, routeKey{ifaceLuid: physLuidV4, dest: ip, prefixLen: 32})
	}
	for _, ip := range v6Endpoints {
		err := AddIpForwardRoute(physLuidV6, 0, ip, 128, gwIPv6, 1)
		if err != nil && !errors.Is(err, ErrRouteAlreadyExists) {
			return fmt.Errorf("installing IPv6 endpoint bypass %s via %s: %w", ip, origGw6, err)
		}
		wantKeys = append(wantKeys, routeKey{ifaceLuid: physLuidV6, dest: ip, prefixLen: 128})
	}
	if missing := VerifyIpForwardRoutes(wantKeys); len(missing) > 0 {
		return fmt.Errorf("installing endpoint bypass: %d route(s) reported success but not visible in table (first missing: %s/%d via LUID %d)",
			len(missing), missing[0].dest, missing[0].prefixLen, missing[0].ifaceLuid)
	}

	// Persist the bypass list so disconnect can target the same rows.
	m.bypassEndpoints = endpoints
	m.bypassPhysLuidV4 = physLuidV4
	m.bypassPhysLuidV6 = physLuidV6
	m.bypassPhysIfIdxV4 = physIfIdxV4
	m.origGateway = origGw
	m.origGatewayV6 = origGw6
	m.origIfIdx6 = origIfIdx6

	// PHASE 3: IPv4 /1 split-route trick (0.0.0.0/1 + 128.0.0.0/1).
	// More specific than the user's existing 0.0.0.0/0 default route, so
	// it takes precedence WITHOUT replacing it — disconnect's row delete
	// automatically restores the underlay's default-route precedence.
	// metric=0 keeps the kernel-computed effective metric purely driven
	// by the tunnel adapter's interface metric (set to 1 by SetDNS).
	if err := AddIpForwardRoute(tunnelLuid, 0, net.IPv4(0, 0, 0, 0), 1, nil, 0); err != nil && !errors.Is(err, ErrRouteAlreadyExists) {
		return fmt.Errorf("adding 0.0.0.0/1: %w", err)
	}
	if err := AddIpForwardRoute(tunnelLuid, 0, net.IPv4(128, 0, 0, 0), 1, nil, 0); err != nil && !errors.Is(err, ErrRouteAlreadyExists) {
		return fmt.Errorf("adding 128.0.0.0/1: %w", err)
	}

	// PHASE 4: IPv6 /1 split routes — best-effort. A box with no IPv6
	// connectivity at all will still pass v4 traffic correctly even if
	// these fail (no kernel-side loop risk because the only IPv6 routes
	// installed are the ones we tried and failed to add).
	v6Unspec := net.IPv6unspecified
	if err := AddIpForwardRoute(tunnelLuid, 0, v6Unspec, 1, nil, 0); err != nil && !errors.Is(err, ErrRouteAlreadyExists) {
		slog.Warn("IPv6 ::/1 split route add failed", "error", err)
	}
	v68000 := net.ParseIP("8000::")
	if err := AddIpForwardRoute(tunnelLuid, 0, v68000, 1, nil, 0); err != nil && !errors.Is(err, ErrRouteAlreadyExists) {
		slog.Warn("IPv6 8000::/1 split route add failed", "error", err)
	}

	return nil
}

func (m *WindowsManager) RemoveRoutes(ifaceName string, allowedIPs []string, fullTunnel bool) error {
	if fullTunnel {
		// Use iphlpapi for the routes we installed via iphlpapi. Each
		// Delete* call is ~microseconds, so we don't need parallelTry's
		// goroutine fan-out anymore — the wall-clock cost of all six
		// deletes is dominated by the kernel's nsi serialisation, not
		// console startup.
		tunnelLuid, _ := convertInterfaceAliasToLuid(ifaceName)
		tryDeleteRoute := func(luid uint64, dest net.IP, prefix uint8, nextHop net.IP, name string) {
			if luid == 0 {
				return
			}
			if err := DeleteIpForwardRoute(luid, 0, dest, prefix, nextHop); err != nil && !errors.Is(err, ErrRouteNotFound) {
				slog.Debug("RemoveRoutes: "+name+" delete failed", "error", err)
			}
		}
		// /1 split routes on the tunnel adapter.
		tryDeleteRoute(tunnelLuid, net.IPv4(0, 0, 0, 0), 1, nil, "0.0.0.0/1")
		tryDeleteRoute(tunnelLuid, net.IPv4(128, 0, 0, 0), 1, nil, "128.0.0.0/1")
		tryDeleteRoute(tunnelLuid, net.IPv6unspecified, 1, nil, "::/1")
		if v6 := net.ParseIP("8000::"); v6 != nil {
			tryDeleteRoute(tunnelLuid, v6, 1, nil, "8000::/1")
		}

		// IPv4 endpoint bypass /32 routes on the physical adapter.
		gwV4 := net.ParseIP(m.origGateway)
		for _, ipStr := range m.bypassEndpoints {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				tryDeleteRoute(m.bypassPhysLuidV4, v4, 32, gwV4, "bypass v4 "+ipStr)
				continue
			}
			gwV6 := net.ParseIP(m.origGatewayV6)
			tryDeleteRoute(m.bypassPhysLuidV6, ip, 128, gwV6, "bypass v6 "+ipStr)
		}

		m.bypassEndpoints = nil
		m.origGateway = ""
		m.origGatewayV6 = ""
		m.origIfIdx6 = ""
		m.bypassPhysLuidV4 = 0
		m.bypassPhysLuidV6 = 0
		m.bypassPhysIfIdxV4 = 0
		return nil
	}
	thunks := make([]func(), 0, len(allowedIPs))
	for _, cidr := range allowedIPs {
		cidr := cidr
		thunks = append(thunks, func() {
			tryRunWin("delete split route", "netsh", "interface", "ip", "delete", "route", cidr, ifaceName)
		})
	}
	parallelTry(thunks...)
	m.splitRoutes = nil
	return nil
}
