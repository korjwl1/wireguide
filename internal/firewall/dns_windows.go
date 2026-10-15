//go:build windows

package firewall

import (
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"unsafe"
)

// EnableDNSProtection installs a single block-everything-port-53 filter
// plus per-server permits, both as a fresh transaction on the existing
// session.
//
// When called without a prior EnableKillSwitch we still open the session
// (DNS protection can be enabled independently to protect against ISP DNS
// hijacking even on a split-tunnel setup).
//
// WFP permits each server by remote address on any interface, so the
// tunnel interfaces in allow are not used to scope the filters — only the
// union of their servers, which the system resolver is also given (issue
// #48). With the kill switch on, unpinned (off-tunnel) servers are left out.
func (f *WindowsFirewall) EnableDNSProtection(allow []DNSAllow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	allow = normalizeDNSAllow(allow, func(string) bool { return true })
	if len(dnsAllowServers(allow)) == 0 {
		// No tunnel with DNS servers is up: remove the rules rather than
		// leave the previous set (or a block-only set) in place.
		return f.disableDNSProtectionLocked()
	}
	return f.installDNSLocked(allow)
}

func (f *WindowsFirewall) txnOps() wfpTxnOps {
	h := f.sessionHandle
	return wfpTxnOps{
		begin:  func() uint32 { return fwpmTransactionBegin0(h) },
		commit: func() uint32 { return fwpmTransactionCommit0(h) },
		abort:  func() uint32 { return fwpmTransactionAbort0(h) },
	}
}

func (f *WindowsFirewall) deleteFilter(id uint64) uint32 {
	return fwpmFilterDeleteById0(f.sessionHandle, id)
}

// installDNSLocked replaces the DNS filter set with one rendered from allow
// (non-empty, normalized) for the current kill-switch mode, in its own
// transaction. Caller MUST hold f.mu. Also used by DisableKillSwitch to
// reinstall DNS protection in the fresh session it rebuilds.
func (f *WindowsFirewall) installDNSLocked(allow []DNSAllow) error {
	if err := f.ensureSession(); err != nil {
		return err
	}
	var ids []uint64
	err := runWFPTransaction(f.txnOps(), "DNS", func() error {
		var err error
		ids, err = f.renderDNSFiltersLocked(allow, f.killSwitchEnabled)
		return err
	})
	if err != nil {
		return err
	}
	f.dnsFilterIDs = ids
	f.dnsAllow = append([]DNSAllow(nil), allow...)
	f.dnsProtectionEnabled = true
	return nil
}

// renderDNSFiltersLocked replaces the tracked DNS filters inside the caller's
// open transaction and returns the new filter IDs. It records nothing: the
// caller updates dnsFilterIDs and flags only after its commit, so an aborted
// transaction leaves the previous set both installed and tracked. Caller
// MUST hold f.mu.
//
// The previous filters are deleted in the SAME transaction: re-enabling
// (reconnect, or a DNS server change) used to stack duplicate filters and
// keep the OLD servers' weight-15 permits — a hole to a resolver the user
// just removed.
func (f *WindowsFirewall) renderDNSFiltersLocked(allow []DNSAllow, killSwitch bool) ([]uint64, error) {
	if err := deleteWFPFilters(f.deleteFilter, f.dnsFilterIDs, "stale DNS"); err != nil {
		return nil, err
	}
	var ids []uint64
	for _, entry := range effectiveDNSAllow(allow, killSwitch) {
		var luid *uint64
		if entry.Interface != "" {
			value, err := resolveInterfaceLUID(entry.Interface)
			if err != nil {
				return nil, fmt.Errorf("resolve DNS interface %q: %w", entry.Interface, err)
			}
			luid = &value
		}
		for _, dns := range entry.Servers {
			ip := net.ParseIP(dns)
			if ip == nil {
				continue
			}
			permitIDs, err := f.permitDNSServer(ip, luid)
			if err != nil {
				return nil, err
			}
			ids = append(ids, permitIDs...)
		}
	}
	// Block UDP/TCP port 53 to everything else — weight 14.
	blockIDs, err := f.blockAllDNS()
	if err != nil {
		return nil, err
	}
	return append(ids, blockIDs...), nil
}

// permitDNSServer installs UDP and TCP permits for one server. A non-nil
// LUID confines the exception to its tunnel, even if routing later drifts.
// Each native call owns its address-mask value and keeps both values alive.
func (f *WindowsFirewall) permitDNSServer(ip net.IP, luid *uint64) ([]uint64, error) {
	if v4 := ip.To4(); v4 != nil {
		udp, err := f.permitDNSv4(ip, v4, 17, "UDP", luid)
		if err != nil {
			return nil, err
		}
		tcp, err := f.permitDNSv4(ip, v4, 6, "TCP", luid)
		if err != nil {
			return nil, err
		}
		return []uint64{udp, tcp}, nil
	}
	var addr [16]byte
	copy(addr[:], ip.To16())
	udp, err := f.permitDNSv6(ip, addr, 17, "UDP", luid)
	if err != nil {
		return nil, err
	}
	tcp, err := f.permitDNSv6(ip, addr, 6, "TCP", luid)
	if err != nil {
		return nil, err
	}
	return []uint64{udp, tcp}, nil
}

// permitDNSv4 installs ONE WFP filter permitting UDP/TCP port 53 traffic
// to a single IPv4 address. The V4_ADDR_MASK struct is heap-allocated
// via `&fwpV4AddrMask{...}` so the GC tracks it through `r` (a real Go
// pointer); the uintptr stored in the condition value field is just a
// number for the kernel to dereference, and runtime.KeepAlive(r) after
// the syscall ensures the GC won't reclaim the heap object mid-call.
func (f *WindowsFirewall) permitDNSv4(ip net.IP, v4 net.IP, proto uint8, protoName string, luid *uint64) (uint64, error) {
	r := &fwpV4AddrMask{
		addr: binary.BigEndian.Uint32(v4),
		mask: 0xFFFFFFFF,
	}
	conds := []fwpmFilterCondition0{
		{fieldKey: guidCondIPProtocol, matchType: matchEqual, conditionValue: uint8Value(proto)},
		{fieldKey: guidCondIPRemotePort, matchType: matchEqual, conditionValue: uint16Value(53)},
		{
			fieldKey:  guidCondIPRemoteAddress,
			matchType: matchEqual,
			conditionValue: fwpConditionValue0{
				dataType: dataTypeV4Address,
				value:    uintptr(unsafe.Pointer(r)),
			},
		},
	}
	if luid != nil {
		conds = append(conds, fwpmFilterCondition0{
			fieldKey:       guidCondIPLocalInterface,
			matchType:      matchEqual,
			conditionValue: uint64ValuePtr(luid),
		})
	}
	id, err := f.addFilter("Permit DNS v4 "+protoName+" "+ip.String(), guidLayerAleAuthConnectV4, actionPermit, 15, conds)
	runtime.KeepAlive(luid)
	runtime.KeepAlive(r)
	runtime.KeepAlive(conds)
	return id, err
}

// permitDNSv6 mirrors permitDNSv4 for IPv6 — single filter, heap-
// allocated V6_ADDR_MASK, KeepAlive immediately after the syscall.
func (f *WindowsFirewall) permitDNSv6(ip net.IP, addr [16]byte, proto uint8, protoName string, luid *uint64) (uint64, error) {
	r := &fwpV6AddrMask{
		addr:         addr,
		prefixLength: 128,
	}
	conds := []fwpmFilterCondition0{
		{fieldKey: guidCondIPProtocol, matchType: matchEqual, conditionValue: uint8Value(proto)},
		{fieldKey: guidCondIPRemotePort, matchType: matchEqual, conditionValue: uint16Value(53)},
		{
			fieldKey:  guidCondIPRemoteAddress,
			matchType: matchEqual,
			conditionValue: fwpConditionValue0{
				dataType: dataTypeV6Address,
				value:    uintptr(unsafe.Pointer(r)),
			},
		},
	}
	if luid != nil {
		conds = append(conds, fwpmFilterCondition0{
			fieldKey:       guidCondIPLocalInterface,
			matchType:      matchEqual,
			conditionValue: uint64ValuePtr(luid),
		})
	}
	id, err := f.addFilter("Permit DNS v6 "+protoName+" "+ip.String(), guidLayerAleAuthConnectV6, actionPermit, 15, conds)
	runtime.KeepAlive(luid)
	runtime.KeepAlive(r)
	runtime.KeepAlive(conds)
	return id, err
}

func (f *WindowsFirewall) blockAllDNS() ([]uint64, error) {
	ids := make([]uint64, 0, len(allConnectLayers)*2)
	for _, layer := range allConnectLayers {
		for _, proto := range []uint8{17, 6} {
			conds := []fwpmFilterCondition0{
				{fieldKey: guidCondIPProtocol, matchType: matchEqual, conditionValue: uint8Value(proto)},
				{fieldKey: guidCondIPRemotePort, matchType: matchEqual, conditionValue: uint16Value(53)},
			}
			id, err := f.addFilter("Block DNS catch-all", layer, actionBlock, 14, conds)
			if err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (f *WindowsFirewall) DisableDNSProtection() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.disableDNSProtectionLocked()
}

// disableDNSProtectionLocked is the body of DisableDNSProtection. Caller
// MUST hold f.mu.
//
// Delete only the DNS filters, by tracked ID, so the kill switch (if up)
// and everything else stay intact. Previously, with no kill switch this tore
// down the whole session, and with a kill switch up it left the port-53
// block filters installed — so a user who then switched to a non-whitelisted
// resolver silently lost all DNS. A failed transaction keeps the flag and
// the IDs: the filters are still installed, and the helper retries while
// IsDNSProtectionEnabled reports them.
func (f *WindowsFirewall) disableDNSProtectionLocked() error {
	if len(f.dnsFilterIDs) > 0 && f.sessionHandle != 0 {
		err := runWFPTransaction(f.txnOps(), "DNS rm", func() error {
			return deleteWFPFilters(f.deleteFilter, f.dnsFilterIDs, "DNS")
		})
		if err != nil {
			return err
		}
	}
	f.dnsFilterIDs = nil
	f.dnsProtectionEnabled = false
	f.dnsAllow = nil
	// Close the session now that the DNS filters are gone — but only if
	// nothing else lives in it, so we don't leak an idle dynamic session.
	if f.sessionIdleLocked() {
		f.closeSession()
	}
	return nil
}

// sessionIdleLocked reports whether the dynamic session holds nothing:
// no kill switch, no endpoint (routing-loop) protection, no DNS filters.
// Closing it cascades every filter, and endpoint protection shares it —
// checking only the kill switch here dropped loop protection whenever DNS
// protection was turned off or re-applied empty (issue #48). Caller MUST
// hold f.mu.
func (f *WindowsFirewall) sessionIdleLocked() bool {
	return !f.killSwitchEnabled && len(f.endpointProtectionFilterIDs) == 0 && len(f.dnsFilterIDs) == 0
}
