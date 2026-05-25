//go:build windows

package firewall

// Endpoint loop protection — always-on WFP filters that close the routing
// loop the bypass /32 host route is meant to prevent.
//
// The bug class this guards against: when a full-tunnel WireGuide install
// has the /1 split routes in place (0.0.0.0/1 + 128.0.0.0/1 through the
// wintun adapter) but the bypass /32 host route to the peer endpoint has
// NOT been installed — or has been installed against a stale/wrong
// nexthop — WireGuard's own encrypted UDP traffic to the peer endpoint
// matches a /1 prefix, re-enters the wintun adapter, gets re-encrypted,
// and goes around again. Userspace wireguard-go on Windows has no fwmark-
// based loop protection (Linux's wg-quick relies on fwmark policy
// routing; macOS's bind uses IP_BOUND_IF), so the host route is the only
// safety net in the default code path.
//
// We install a narrow BLOCK filter at ALE_AUTH_CONNECT_V4 / V6 that fires
// only when ALL of the following match:
//
//   protocol      = UDP (17)
//   remote IP     = peer endpoint /32 or /128
//   remote port   = peer endpoint port (when known)
//   local LUID    = the tunnel adapter
//
// When the routing decision picks the tunnel (loop case) the filter
// fires and the kernel drops the connect, so wireguard-go sees a clean
// send-error and retries — no exponential traffic amplification. When
// the routing decision correctly picks the physical adapter (the normal
// case), the local-LUID condition doesn't match and the filter is
// inert. We do NOT install a corresponding PERMIT on the physical
// adapter: that would only be necessary if the kill switch's catch-all
// is also in force, and the kill switch's own per-tunnel endpoint
// permit (installTunnelFiltersLocked) already covers that path.
//
// Weight 13 — strictly above the kill switch's per-tunnel permits
// (weight 12) so the block wins even when both feature sets are active
// on the same connect. Strictly below DNS protection's permits/blocks
// (weights 14/15), but those match port-53 traffic only and our endpoint
// port is never 53 in practice, so the relative ordering with DNS is
// theoretical. Loopback (also weight 13) only matches 127.0.0.0/8 /
// ::1 — disjoint from any real peer endpoint, no tie.

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strconv"
	"unsafe"
)

// endpointProtectionWeight sits above weight 12 (kill switch's per-tunnel
// permits) and below weight 14 (DNS block-all). See the file header for
// the full ordering rationale.
const endpointProtectionWeight uint8 = 13

// EnableEndpointProtection installs always-on routing-loop protection
// for one tunnel's worth of peer endpoints. Idempotent for the same
// (tunnelInterfaceName, endpoints) pair: a repeated call with the same
// endpoints is treated as a refresh (old filters removed, fresh ones
// installed) so reconnects don't accumulate stale filter IDs.
//
// `endpoints` items are "ip:port" strings — the same form
// tunnel.Manager.ResolvedEndpoints returns. Bare "ip" (no port) is
// tolerated and produces a port-agnostic filter, but the narrower
// match with port is strongly preferred.
//
// Returns nil + no work when `endpoints` is empty (split-tunnel /
// table=off configurations don't need this protection because their
// route table never traps the encrypted traffic).
func (f *WindowsFirewall) EnableEndpointProtection(tunnelInterfaceName string, endpoints []string) error {
	if tunnelInterfaceName == "" {
		return fmt.Errorf("EnableEndpointProtection: empty interface name")
	}
	if len(endpoints) == 0 {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enableEndpointProtectionLocked(tunnelInterfaceName, endpoints)
}

// enableEndpointProtectionLocked is the lock-held implementation. Used
// directly by DisableKillSwitch's snapshot-and-rebuild path, where the
// caller is already inside f.mu.
func (f *WindowsFirewall) enableEndpointProtectionLocked(tunnelInterfaceName string, endpoints []string) error {
	if err := f.ensureSession(); err != nil {
		return fmt.Errorf("endpoint protection: ensureSession: %w", err)
	}

	// If we already have filters for this tunnel, remove them first so a
	// reconnect with a different resolved endpoint IP doesn't leak the
	// old filter forever.
	if existing := f.endpointProtectionFilterIDs[tunnelInterfaceName]; len(existing) > 0 {
		if err := f.removeEndpointProtectionFilters(tunnelInterfaceName); err != nil {
			slog.Warn("endpoint protection: pre-install cleanup failed; continuing",
				"interface", tunnelInterfaceName, "error", err)
		}
	}

	luid, err := resolveInterfaceLUID(tunnelInterfaceName)
	if err != nil {
		return fmt.Errorf("endpoint protection: resolve tunnel LUID: %w", err)
	}

	if status := fwpmTransactionBegin0(f.sessionHandle); status != 0 {
		return fmt.Errorf("endpoint protection: FwpmTransactionBegin0: 0x%x", status)
	}
	committed := false
	defer func() {
		if !committed {
			fwpmTransactionAbort0(f.sessionHandle)
		}
	}()

	var ids []uint64
	for _, ep := range endpoints {
		ipStr, portStr, _ := net.SplitHostPort(ep)
		if ipStr == "" {
			// "ip:" or malformed → fall back to using the whole string as the IP
			ipStr = ep
			portStr = ""
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			slog.Warn("endpoint protection: skipping unparsable endpoint", "endpoint", ep)
			continue
		}
		var port uint16
		if portStr != "" {
			p, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				slog.Warn("endpoint protection: skipping endpoint with bad port", "endpoint", ep, "error", err)
				continue
			}
			port = uint16(p)
		}
		id, err := f.installEndpointBlockFilter(ip, port, luid)
		if err != nil {
			return fmt.Errorf("endpoint protection: install filter for %s: %w", ip, err)
		}
		ids = append(ids, id)
	}

	if len(ids) == 0 {
		// Every endpoint was unparsable — refuse to commit an empty
		// transaction; surface to the caller so connectPhases can roll
		// back the tunnel rather than bring it up unprotected.
		return fmt.Errorf("endpoint protection: no valid endpoints in %v", endpoints)
	}

	if status := fwpmTransactionCommit0(f.sessionHandle); status != 0 {
		return fmt.Errorf("endpoint protection: FwpmTransactionCommit0: 0x%x", status)
	}
	committed = true

	if f.endpointProtectionFilterIDs == nil {
		f.endpointProtectionFilterIDs = make(map[string][]uint64, 1)
	}
	if f.endpointProtectionState == nil {
		f.endpointProtectionState = make(map[string][]string, 1)
	}
	f.endpointProtectionFilterIDs[tunnelInterfaceName] = ids
	stateCopy := make([]string, len(endpoints))
	copy(stateCopy, endpoints)
	f.endpointProtectionState[tunnelInterfaceName] = stateCopy

	slog.Info("endpoint loop protection enabled",
		"interface", tunnelInterfaceName,
		"endpoints", len(endpoints),
		"filters", len(ids))
	return nil
}

// DisableEndpointProtection removes the BLOCK filters installed for one
// tunnel. Idempotent: returns nil when there's nothing tracked for the
// name (e.g. split tunnel that never called Enable, or a double-call).
func (f *WindowsFirewall) DisableEndpointProtection(tunnelInterfaceName string) error {
	if tunnelInterfaceName == "" {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sessionHandle == 0 {
		// Session already gone — filters with it. Just drop tracked state.
		delete(f.endpointProtectionFilterIDs, tunnelInterfaceName)
		delete(f.endpointProtectionState, tunnelInterfaceName)
		return nil
	}
	return f.removeEndpointProtectionFilters(tunnelInterfaceName)
}

// removeEndpointProtectionFilters deletes the filters tracked for one
// tunnel and clears the corresponding map entries. Caller MUST hold
// f.mu. Wrapped in its own transaction; safe to call when no work is
// pending (returns nil).
func (f *WindowsFirewall) removeEndpointProtectionFilters(tunnelInterfaceName string) error {
	ids := f.endpointProtectionFilterIDs[tunnelInterfaceName]
	if len(ids) == 0 {
		return nil
	}
	if status := fwpmTransactionBegin0(f.sessionHandle); status != 0 {
		return fmt.Errorf("endpoint protection: FwpmTransactionBegin0(rm): 0x%x", status)
	}
	committed := false
	defer func() {
		if !committed {
			fwpmTransactionAbort0(f.sessionHandle)
		}
	}()
	for _, id := range ids {
		if status := fwpmFilterDeleteById0(f.sessionHandle, id); status != 0 {
			slog.Warn("endpoint protection: filter delete failed (continuing)",
				"interface", tunnelInterfaceName,
				"filter_id", id,
				"status", fmt.Sprintf("0x%x", status))
		}
	}
	if status := fwpmTransactionCommit0(f.sessionHandle); status != 0 {
		return fmt.Errorf("endpoint protection: FwpmTransactionCommit0(rm): 0x%x", status)
	}
	committed = true
	delete(f.endpointProtectionFilterIDs, tunnelInterfaceName)
	delete(f.endpointProtectionState, tunnelInterfaceName)
	return nil
}

// installEndpointBlockFilter installs ONE BLOCK filter for one endpoint
// IP+port on the tunnel LUID, at the correct ALE_AUTH_CONNECT layer for
// the IP family. Returns the WFP filter ID. Caller MUST hold f.mu AND
// must be inside a WFP transaction.
//
// `port == 0` means "no port match"; that path is reserved for callers
// that received a bare-IP endpoint string (no port). WireGuide's
// resolvedEndpoints always carries a port so the port==0 branch is a
// defensive fallback, not the hot path.
func (f *WindowsFirewall) installEndpointBlockFilter(ip net.IP, port uint16, tunnelLUID uint64) (uint64, error) {
	luidCopy := tunnelLUID
	if v4 := ip.To4(); v4 != nil {
		r := &fwpV4AddrMask{
			addr: binary.BigEndian.Uint32(v4),
			mask: 0xFFFFFFFF,
		}
		conds := []fwpmFilterCondition0{
			{fieldKey: guidCondIPProtocol, matchType: matchEqual, conditionValue: uint8Value(17)},
			{
				fieldKey:  guidCondIPRemoteAddress,
				matchType: matchEqual,
				conditionValue: fwpConditionValue0{
					dataType: dataTypeV4Address,
					value:    uintptr(unsafe.Pointer(r)),
				},
			},
			{
				fieldKey:       guidCondIPLocalInterface,
				matchType:      matchEqual,
				conditionValue: uint64ValuePtr(&luidCopy),
			},
		}
		if port != 0 {
			conds = append(conds, fwpmFilterCondition0{
				fieldKey: guidCondIPRemotePort, matchType: matchEqual, conditionValue: uint16Value(port),
			})
		}
		id, err := f.addFilter("Block WG endpoint loop v4 "+ip.String(),
			guidLayerAleAuthConnectV4, actionBlock, endpointProtectionWeight, conds)
		runtime.KeepAlive(r)
		runtime.KeepAlive(conds)
		runtime.KeepAlive(&luidCopy)
		return id, err
	}
	r := &fwpV6AddrMask{prefixLength: 128}
	copy(r.addr[:], ip.To16())
	conds := []fwpmFilterCondition0{
		{fieldKey: guidCondIPProtocol, matchType: matchEqual, conditionValue: uint8Value(17)},
		{
			fieldKey:  guidCondIPRemoteAddress,
			matchType: matchEqual,
			conditionValue: fwpConditionValue0{
				dataType: dataTypeV6Address,
				value:    uintptr(unsafe.Pointer(r)),
			},
		},
		{
			fieldKey:       guidCondIPLocalInterface,
			matchType:      matchEqual,
			conditionValue: uint64ValuePtr(&luidCopy),
		},
	}
	if port != 0 {
		conds = append(conds, fwpmFilterCondition0{
			fieldKey: guidCondIPRemotePort, matchType: matchEqual, conditionValue: uint16Value(port),
		})
	}
	id, err := f.addFilter("Block WG endpoint loop v6 "+ip.String(),
		guidLayerAleAuthConnectV6, actionBlock, endpointProtectionWeight, conds)
	runtime.KeepAlive(r)
	runtime.KeepAlive(conds)
	runtime.KeepAlive(&luidCopy)
	return id, err
}
