//go:build windows

package firewall

// Endpoint loop protection blocks encrypted UDP addressed to a peer when the
// route sends it through its own tunnel adapter. Filters match UDP, peer IP,
// peer port when known, and tunnel LUID, leaving the physical adapter unaffected.
//
// ALE_AUTH_CONNECT enforces flow authorization. OUTBOUND_TRANSPORT checks each
// datagram, including flows with a previously cached ALE permit. The transport
// filter also enforces loop blocking for a UDP:53 peer whose ALE classification
// may match the higher-weight DNS permits. We install both layers per family.

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
// permits). DNS weights apply at ALE; the independent outbound-transport
// filter remains effective when an ALE DNS permit wins.
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

// enableEndpointProtectionLocked replaces one interface's filters in a single
// transaction. Caller holds f.mu; failed replacement preserves the old set.
func (f *WindowsFirewall) enableEndpointProtectionLocked(tunnelInterfaceName string, endpoints []string) error {
	if err := f.ensureSession(); err != nil {
		return fmt.Errorf("endpoint protection: ensureSession: %w", err)
	}

	luid, err := resolveInterfaceLUID(tunnelInterfaceName)
	if err != nil {
		return fmt.Errorf("endpoint protection: resolve tunnel LUID: %w", err)
	}

	var ids []uint64
	err = runWFPTransaction(f.txnOps(), "endpoint-replace", func() error {
		if err := deleteWFPFilters(f.deleteFilter, f.endpointProtectionFilterIDs[tunnelInterfaceName], "old endpoint"); err != nil {
			return err
		}
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
			filterIDs, err := f.installEndpointBlockFilter(ip, port, luid)
			if err != nil {
				return fmt.Errorf("endpoint protection: install filter for %s: %w", ip, err)
			}
			ids = append(ids, filterIDs...)
		}

		if len(ids) == 0 {
			// Every endpoint was unparsable — refuse to commit an empty
			// transaction; surface to the caller so connectPhases can roll
			// back the tunnel rather than bring it up unprotected.
			return fmt.Errorf("endpoint protection: no valid endpoints in %v", endpoints)
		}
		return nil
	})
	if err != nil {
		return err
	}

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
	if err := runWFPTransaction(f.txnOps(), "endpoint-remove", func() error {
		return deleteWFPFilters(f.deleteFilter, ids, "endpoint")
	}); err != nil {
		return err
	}
	delete(f.endpointProtectionFilterIDs, tunnelInterfaceName)
	delete(f.endpointProtectionState, tunnelInterfaceName)
	return nil
}

// installEndpointBlockFilter installs BLOCK filters for one endpoint
// IP+port on the tunnel LUID, at BOTH the ALE_AUTH_CONNECT layer (per-
// flow) AND the OUTBOUND_TRANSPORT layer (per-packet) for the matching
// IP family. Returns every WFP filter ID created. Caller MUST hold
// f.mu AND must be inside a WFP transaction.
//
// `port == 0` means "no port match"; that path is reserved for callers
// that received a bare-IP endpoint string (no port). WireGuide's
// resolvedEndpoints always carries a port so the port==0 branch is a
// defensive fallback, not the hot path.
func (f *WindowsFirewall) installEndpointBlockFilter(ip net.IP, port uint16, tunnelLUID uint64) ([]uint64, error) {
	luidCopy := tunnelLUID
	if v4 := ip.To4(); v4 != nil {
		r := &fwpV4AddrMask{
			addr: binary.BigEndian.Uint32(v4),
			mask: 0xFFFFFFFF,
		}
		buildConds := func() []fwpmFilterCondition0 {
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
			return conds
		}
		ids := make([]uint64, 0, 2)
		aleConds := buildConds()
		aleID, err := f.addFilter("Block WG endpoint loop ALE v4 "+ip.String(),
			guidLayerAleAuthConnectV4, actionBlock, endpointProtectionWeight, aleConds)
		runtime.KeepAlive(aleConds)
		if err != nil {
			runtime.KeepAlive(r)
			runtime.KeepAlive(&luidCopy)
			return ids, err
		}
		ids = append(ids, aleID)
		txConds := buildConds()
		txID, err := f.addFilter("Block WG endpoint loop TX v4 "+ip.String(),
			guidLayerOutboundTransportV4, actionBlock, endpointProtectionWeight, txConds)
		runtime.KeepAlive(txConds)
		runtime.KeepAlive(r)
		runtime.KeepAlive(&luidCopy)
		if err != nil {
			return ids, err
		}
		ids = append(ids, txID)
		return ids, nil
	}
	r := &fwpV6AddrMask{prefixLength: 128}
	copy(r.addr[:], ip.To16())
	buildConds := func() []fwpmFilterCondition0 {
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
		return conds
	}
	ids := make([]uint64, 0, 2)
	aleConds := buildConds()
	aleID, err := f.addFilter("Block WG endpoint loop ALE v6 "+ip.String(),
		guidLayerAleAuthConnectV6, actionBlock, endpointProtectionWeight, aleConds)
	runtime.KeepAlive(aleConds)
	if err != nil {
		runtime.KeepAlive(r)
		runtime.KeepAlive(&luidCopy)
		return ids, err
	}
	ids = append(ids, aleID)
	txConds := buildConds()
	txID, err := f.addFilter("Block WG endpoint loop TX v6 "+ip.String(),
		guidLayerOutboundTransportV6, actionBlock, endpointProtectionWeight, txConds)
	runtime.KeepAlive(txConds)
	runtime.KeepAlive(r)
	runtime.KeepAlive(&luidCopy)
	if err != nil {
		return ids, err
	}
	ids = append(ids, txID)
	return ids, nil
}
