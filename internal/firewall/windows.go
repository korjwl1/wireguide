//go:build windows

package firewall

import (
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WindowsFirewall implements the kill-switch and DNS-protection feature set
// directly via the Windows Filtering Platform (WFP) — no netsh, no
// PowerShell, no system-wide policy mutation. A dynamic WFP session holds
// every filter; closing the session removes them atomically.
//
// Concurrency invariant: every public mutator takes f.mu before calling
// ensureSession + Begin/Commit/Abort. This makes WFP transactions
// strictly serial — they cannot interleave even if EnableKillSwitch and
// EnableDNSProtection are called from different goroutines, so the
// per-session "single transaction at a time" rule (FwpmTransactionBegin0
// returns FWP_E_TXN_IN_PROGRESS otherwise) is never violated.
//
// Why WFP and not WFAS (`netsh advfirewall`):
//
//   - WFAS rules are evaluated AFTER WFP filters and apply at a coarser
//     granularity. A kill-switch built on WFAS either requires changing
//     the default policy (which we used to do, with disastrous side
//     effects on Windows Update / Store / RPC) or accepting that "block
//     X except Y" doesn't work without -OverrideBlockRules acrobatics.
//   - WFP gives us per-filter weights, transactional safety, and instant
//     removal on session close. It's also what the official WireGuard
//     Windows client uses (see wireguard-windows/tunnel/firewall).
//
// Architecture (filter weights — higher fires first):
//
//	weight 13  permit loopback (127.0.0.0/8, ::1)
//	weight 12  permit on the tunnel interface (LUID match)
//	weight 12  permit DHCP IPv4 (UDP 67/68) and IPv6 (UDP 546/547)
//	weight 12  permit IPv6 NDP (ICMPv6)
//	weight 14  block port 53 to non-allowed servers (DNS protection)
//	weight 15  permit port 53 to the configured DNS servers
//	weight  0  block everything else (the kill switch's catch-all)
//
// The DNS layer is split into its own filter set so EnableDNSProtection
// can be toggled independently of the kill switch.
type WindowsFirewall struct {
	mu sync.Mutex

	sessionHandle uintptr
	providerKey   windows.GUID
	sublayerKey   windows.GUID

	killSwitchEnabled    bool
	dnsProtectionEnabled bool
}

func NewPlatformFirewall() FirewallManager {
	return &WindowsFirewall{}
}

// ensureSession opens a WFP session and registers our provider + sublayer
// if not already done. Idempotent. Caller MUST hold f.mu.
func (f *WindowsFirewall) ensureSession() error {
	if f.sessionHandle != 0 {
		return nil
	}
	displayName := utf16Ptr("WireGuide")
	displayDesc := utf16Ptr("WireGuide kill-switch and DNS-protection filters")
	sess := fwpmSession0{
		displayData:          fwpmDisplayData0{name: displayName, description: displayDesc},
		flags:                fwpmSessionFlagDynamic,
		txnWaitTimeoutInMSec: 0xFFFFFFFF, // INFINITE
	}
	var handle uintptr
	if status := fwpmEngineOpen0(&sess, &handle); status != 0 {
		return fmt.Errorf("FwpmEngineOpen0: 0x%x", status)
	}

	// Distinct provider GUID and sublayer GUID — generated once per
	// session so concurrent helpers can't collide.
	providerKey, err := windows.GenerateGUID()
	if err != nil {
		fwpmEngineClose0(handle)
		return fmt.Errorf("GenerateGUID(provider): %w", err)
	}
	sublayerKey, err := windows.GenerateGUID()
	if err != nil {
		fwpmEngineClose0(handle)
		return fmt.Errorf("GenerateGUID(sublayer): %w", err)
	}

	provider := fwpmProvider0{
		providerKey: providerKey,
		displayData: fwpmDisplayData0{name: utf16Ptr("WireGuide-Provider")},
	}
	if status := fwpmProviderAdd0(handle, &provider); status != 0 {
		fwpmEngineClose0(handle)
		return fmt.Errorf("FwpmProviderAdd0: 0x%x", status)
	}

	sublayer := fwpmSubLayer0{
		subLayerKey: sublayerKey,
		displayData: fwpmDisplayData0{name: utf16Ptr("WireGuide-SubLayer")},
		providerKey: &providerKey,
		// MAXUSHORT — same value the official WireGuard-Windows client
		// uses (`^uint16(0)` in tunnel/firewall/blocker.go). There is no
		// documented "reserved" higher slot; this is the absolute
		// maximum and the official client trusts it to dominate every
		// third-party VPN sublayer. WireGuard-Windows also does no
		// coexistence negotiation — it just sets max weight and wins
		// any tie by virtue of being installed last (BFE evaluates
		// equal-weight sublayers in registration order).
		weight: 0xFFFF,
	}
	if status := fwpmSubLayerAdd0(handle, &sublayer); status != 0 {
		fwpmEngineClose0(handle)
		return fmt.Errorf("FwpmSubLayerAdd0: 0x%x", status)
	}

	f.sessionHandle = handle
	f.providerKey = providerKey
	f.sublayerKey = sublayerKey
	return nil
}

// closeSession tears down every filter we installed by closing the dynamic
// session. Idempotent. Caller MUST hold f.mu.
func (f *WindowsFirewall) closeSession() {
	if f.sessionHandle == 0 {
		return
	}
	fwpmEngineClose0(f.sessionHandle)
	f.sessionHandle = 0
	f.killSwitchEnabled = false
	f.dnsProtectionEnabled = false
}

// resolveInterfaceLUID looks up the LUID of the tunnel interface by its
// friendly name (as wintun creates it). The LUID is what WFP filters key
// on — interface index would also work but LUIDs are stable across
// re-creation, which matters for crash recovery.
func resolveInterfaceLUID(ifaceName string) (uint64, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	target := ""
	for _, ifi := range ifaces {
		if ifi.Name == ifaceName {
			target = ifaceName
			break
		}
	}
	if target == "" {
		return 0, fmt.Errorf("interface %q not found", ifaceName)
	}
	// Resolve LUID via iphlpapi ConvertInterfaceAliasToLuid.
	procConvertAliasToLuid := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("ConvertInterfaceAliasToLuid")
	utf16, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return 0, err
	}
	var luid uint64
	ret, _, _ := procConvertAliasToLuid.Call(
		uintptr(unsafe.Pointer(utf16)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("ConvertInterfaceAliasToLuid: 0x%x", ret)
	}
	return luid, nil
}

// addFilter installs one filter. Conditions are passed as a slice; the
// kernel copies them out synchronously during FwpmFilterAdd0, so we only
// need to keep them alive across the syscall. runtime.KeepAlive is
// mandatory because uintptr(unsafe.Pointer(&v)) drops the GC tracking
// reference — without it the compiler may free the backing memory
// while the syscall is still reading it.
func (f *WindowsFirewall) addFilter(name string, layerKey windows.GUID, action uint32, weight uint16, conditions []fwpmFilterCondition0) (uint64, error) {
	displayName := utf16Ptr(name)
	filter := fwpmFilter0{
		displayData:         fwpmDisplayData0{name: displayName},
		flags:               fwpmFilterFlagNone,
		providerKey:         &f.providerKey,
		layerKey:            layerKey,
		subLayerKey:         f.sublayerKey,
		weight:              weight16(weight),
		numFilterConditions: uint32(len(conditions)),
		action:              fwpmAction0{actionType: action},
	}
	if len(conditions) > 0 {
		filter.filterCondition = &conditions[0]
	}
	id, status := fwpmFilterAdd0(f.sessionHandle, &filter)
	// Keep the filter struct + conditions slice live until the kernel call
	// fully returns. Each condition's conditionValue.value field may also
	// hold uintptrs into caller-owned memory (V4_ADDR_MASK / V6_ADDR_MASK
	// structs); those are the caller's responsibility to KeepAlive after
	// addFilter returns.
	runtime.KeepAlive(&filter)
	runtime.KeepAlive(conditions)
	runtime.KeepAlive(displayName)
	if status != 0 {
		return 0, fmt.Errorf("FwpmFilterAdd0(%s): 0x%x", name, status)
	}
	return id, nil
}

// EnableKillSwitch installs the full WFP filter set. ifaceAddresses is the
// list of tunnel-interface IPs (for anti-spoof); we don't need it on
// Windows because the tunnel LUID match handles the same role
// implicitly.
func (f *WindowsFirewall) EnableKillSwitch(interfaceName string, _ []string, endpoints []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.killSwitchEnabled {
		return nil
	}
	if err := f.ensureSession(); err != nil {
		return err
	}

	luid, err := resolveInterfaceLUID(interfaceName)
	if err != nil {
		return fmt.Errorf("resolve tunnel LUID: %w", err)
	}

	// Start a transaction so a mid-way error rolls back cleanly.
	if status := fwpmTransactionBegin0(f.sessionHandle); status != 0 {
		return fmt.Errorf("FwpmTransactionBegin0: 0x%x", status)
	}
	committed := false
	defer func() {
		if !committed {
			fwpmTransactionAbort0(f.sessionHandle)
		}
	}()

	// Two layers we install everything on: IPv4 and IPv6 outbound connect.
	// Use the package-level array to avoid per-call slice allocation.
	layers := allConnectLayers[:]

	// (1) Permit on tunnel interface — weight 12.
	for _, layer := range layers {
		luidCopy := luid
		conds := []fwpmFilterCondition0{
			{
				fieldKey:       guidCondIPLocalInterface,
				matchType:      matchEqual,
				conditionValue: uint64ValuePtr(&luidCopy),
			},
		}
		if _, err := f.addFilter("Permit tunnel", layer, actionPermit, 12, conds); err != nil {
			return err
		}
		// runtime.KeepAlive keeps the LUID pointer reachable across the
		// kernel call — without it, Go's escape analysis may stack-
		// allocate luidCopy and free it before fwpmFilterAdd0 copies the
		// value out. `_ = luidCopy` is NOT sufficient: the compiler can
		// elide it as dead code.
		runtime.KeepAlive(&luidCopy)
		runtime.KeepAlive(conds)
	}

	// (2) Permit loopback — weight 13. Loopback uses LOCAL_ADDRESS, not
	// interface LUID, on these layers. Easiest match: condition on
	// remote address in 127.0.0.0/8 / ::1.
	if err := f.permitLoopback(); err != nil {
		return err
	}

	// (3) Permit DHCP IPv4 (UDP 67/68) and IPv6 (UDP 546/547) — weight 12.
	if err := f.permitDHCP(); err != nil {
		return err
	}

	// (4) Permit ICMPv6 NDP — weight 12. NDP types 133-137 are needed
	// for IPv6 router solicitation/advertisement and neighbor discovery.
	// At the ALE_AUTH_CONNECT layer we can't filter on ICMPv6 type
	// directly; we permit all ICMPv6 destined to link-local fe80::/10,
	// which covers NDP without leaking ping-of-death style abuse.
	if err := f.permitICMPv6LinkLocal(); err != nil {
		return err
	}

	// (5) Permit each WG endpoint IP outbound — weight 12. This lets the
	// encrypted WG packets reach the server even with the catch-all in
	// place.
	for _, ep := range endpoints {
		ip, _, _ := net.SplitHostPort(ep)
		if ip == "" {
			ip = ep
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if err := f.permitEndpoint(parsed); err != nil {
			return err
		}
	}

	// (6) Catch-all block — weight 0.
	for _, layer := range layers {
		if _, err := f.addFilter("Block all (catch-all)", layer, actionBlock, 0, nil); err != nil {
			return err
		}
	}

	if status := fwpmTransactionCommit0(f.sessionHandle); status != 0 {
		return fmt.Errorf("FwpmTransactionCommit0: 0x%x", status)
	}
	committed = true
	f.killSwitchEnabled = true
	return nil
}

// permitLoopback permits outbound to 127.0.0.0/8 (IPv4) and ::1/128 (IPv6).
// Implemented as two conditions per layer matching remote address ranges.
//
// Loopback connections at the ALE layer don't typically need an explicit
// permit because Windows treats loopback specially, but we add it for
// belt-and-suspenders compatibility with apps that bind explicit loopback
// sockets.
func (f *WindowsFirewall) permitLoopback() error {
	// IPv4 loopback /8: address 127.0.0.0, mask 255.0.0.0.
	var v4Range = struct {
		addr uint32
		mask uint32
	}{addr: 0x7F000000, mask: 0xFF000000}

	// We use V4_ADDR_MASK conditioned via dataTypeV4Address (FWP_V4_ADDR_MASK = 12).
	// The condition value points at a 64-bit struct {uint32 addr; uint32 mask}.
	cond4 := []fwpmFilterCondition0{
		{
			fieldKey:  guidCondIPRemoteAddress,
			matchType: matchEqual,
			conditionValue: fwpConditionValue0{
				dataType: dataTypeV4Address,
				value:    uintptr(unsafe.Pointer(&v4Range)),
			},
		},
	}
	if _, err := f.addFilter("Permit loopback v4", guidLayerAleAuthConnectV4, actionPermit, 13, cond4); err != nil {
		return err
	}
	runtime.KeepAlive(&v4Range)
	runtime.KeepAlive(cond4)

	// IPv6 loopback ::1 — single host. Use BYTE_ARRAY16 via a 16-byte buffer.
	var v6Loop [16]byte
	v6Loop[15] = 1
	v6Mask := [16]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	var v6Range = struct {
		addr [16]byte
		mask [16]byte
	}{addr: v6Loop, mask: v6Mask}
	cond6 := []fwpmFilterCondition0{
		{
			fieldKey:  guidCondIPRemoteAddress,
			matchType: matchEqual,
			conditionValue: fwpConditionValue0{
				dataType: dataTypeV6Address,
				value:    uintptr(unsafe.Pointer(&v6Range)),
			},
		},
	}
	if _, err := f.addFilter("Permit loopback v6", guidLayerAleAuthConnectV6, actionPermit, 13, cond6); err != nil {
		return err
	}
	runtime.KeepAlive(&v6Range)
	runtime.KeepAlive(cond6)
	runtime.KeepAlive(&v6Loop)
	runtime.KeepAlive(&v6Mask)
	return nil
}

// permitDHCP permits UDP 67/68 (IPv4 DHCP) and UDP 546/547 (IPv6 DHCPv6).
func (f *WindowsFirewall) permitDHCP() error {
	// IPv4 DHCP: UDP, local port 68, remote port 67.
	v4Conds := []fwpmFilterCondition0{
		{fieldKey: guidCondIPProtocol, matchType: matchEqual, conditionValue: uint8Value(17)},
		{fieldKey: guidCondIPLocalPort, matchType: matchEqual, conditionValue: uint16Value(68)},
		{fieldKey: guidCondIPRemotePort, matchType: matchEqual, conditionValue: uint16Value(67)},
	}
	if _, err := f.addFilter("Permit DHCPv4", guidLayerAleAuthConnectV4, actionPermit, 12, v4Conds); err != nil {
		return err
	}

	// IPv6 DHCPv6: UDP, local port 546, remote port 547.
	v6Conds := []fwpmFilterCondition0{
		{fieldKey: guidCondIPProtocol, matchType: matchEqual, conditionValue: uint8Value(17)},
		{fieldKey: guidCondIPLocalPort, matchType: matchEqual, conditionValue: uint16Value(546)},
		{fieldKey: guidCondIPRemotePort, matchType: matchEqual, conditionValue: uint16Value(547)},
	}
	if _, err := f.addFilter("Permit DHCPv6", guidLayerAleAuthConnectV6, actionPermit, 12, v6Conds); err != nil {
		return err
	}
	return nil
}

// permitICMPv6LinkLocal permits ICMPv6 (protocol 58) to fe80::/10.
func (f *WindowsFirewall) permitICMPv6LinkLocal() error {
	// fe80::/10 — first 10 bits = 0xfe80.
	var ll = struct {
		addr [16]byte
		mask [16]byte
	}{
		addr: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		mask: [16]byte{0xff, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	conds := []fwpmFilterCondition0{
		{fieldKey: guidCondIPProtocol, matchType: matchEqual, conditionValue: uint8Value(58)},
		{
			fieldKey:  guidCondIPRemoteAddress,
			matchType: matchEqual,
			conditionValue: fwpConditionValue0{
				dataType: dataTypeV6Address,
				value:    uintptr(unsafe.Pointer(&ll)),
			},
		},
	}
	if _, err := f.addFilter("Permit NDP (ICMPv6 link-local)", guidLayerAleAuthConnectV6, actionPermit, 12, conds); err != nil {
		return err
	}
	runtime.KeepAlive(&ll)
	runtime.KeepAlive(conds)
	return nil
}

// permitEndpoint adds a single permit filter for traffic to one peer
// endpoint IP. UDP-only (WG uses UDP).
func (f *WindowsFirewall) permitEndpoint(ip net.IP) error {
	if v4 := ip.To4(); v4 != nil {
		// Endpoint /32 in V4_ADDR_MASK form.
		var r = struct {
			addr uint32
			mask uint32
		}{
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
					value:    uintptr(unsafe.Pointer(&r)),
				},
			},
		}
		if _, err := f.addFilter("Permit WG endpoint v4 "+ip.String(), guidLayerAleAuthConnectV4, actionPermit, 12, conds); err != nil {
			return err
		}
		runtime.KeepAlive(&r)
		runtime.KeepAlive(conds)
		return nil
	}
	// IPv6 endpoint /128.
	var addr [16]byte
	copy(addr[:], ip.To16())
	mask := [16]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	var r = struct {
		addr [16]byte
		mask [16]byte
	}{addr: addr, mask: mask}
	conds := []fwpmFilterCondition0{
		{fieldKey: guidCondIPProtocol, matchType: matchEqual, conditionValue: uint8Value(17)},
		{
			fieldKey:  guidCondIPRemoteAddress,
			matchType: matchEqual,
			conditionValue: fwpConditionValue0{
				dataType: dataTypeV6Address,
				value:    uintptr(unsafe.Pointer(&r)),
			},
		},
	}
	if _, err := f.addFilter("Permit WG endpoint v6 "+ip.String(), guidLayerAleAuthConnectV6, actionPermit, 12, conds); err != nil {
		return err
	}
	runtime.KeepAlive(&r)
	runtime.KeepAlive(conds)
	runtime.KeepAlive(&addr)
	runtime.KeepAlive(&mask)
	return nil
}

func (f *WindowsFirewall) DisableKillSwitch() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Closing the dynamic session removes every filter in one shot. If
	// DNS protection is also active it will be torn down together —
	// that's acceptable because the DNS rules only matter when a tunnel
	// is up, and DisableKillSwitch implies the user is taking the
	// tunnel down.
	f.closeSession()
	return nil
}

// EnableDNSProtection installs a single block-everything-port-53 filter
// plus per-server permits, both as a fresh transaction on the existing
// session.
//
// When called without a prior EnableKillSwitch we still open the session
// (DNS protection can be enabled independently to protect against ISP DNS
// hijacking even on a split-tunnel setup).
func (f *WindowsFirewall) EnableDNSProtection(interfaceName string, dnsServers []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(dnsServers) == 0 {
		return nil
	}
	if err := f.ensureSession(); err != nil {
		return err
	}

	if status := fwpmTransactionBegin0(f.sessionHandle); status != 0 {
		return fmt.Errorf("FwpmTransactionBegin0(DNS): 0x%x", status)
	}
	committed := false
	defer func() {
		if !committed {
			fwpmTransactionAbort0(f.sessionHandle)
		}
	}()

	// Permit DNS to each whitelisted server first — weight 15 (higher
	// than the block below). Both UDP and TCP, because DNS-over-TCP is a
	// legitimate fallback for >512-byte responses.
	for _, dns := range dnsServers {
		ip := net.ParseIP(dns)
		if ip == nil {
			continue
		}
		if err := f.permitDNSServer(ip); err != nil {
			return err
		}
	}

	// Block UDP/TCP port 53 to everything else — weight 14.
	if err := f.blockAllDNS(); err != nil {
		return err
	}

	if status := fwpmTransactionCommit0(f.sessionHandle); status != 0 {
		return fmt.Errorf("FwpmTransactionCommit0(DNS): 0x%x", status)
	}
	committed = true
	f.dnsProtectionEnabled = true
	return nil
}

// permitDNSServer installs two filters (UDP+TCP) per address family for
// one whitelisted DNS server. The UDP and TCP cases use separate condition
// slices so the unsafe-pointer aliasing in conditionValue.value stays
// clearly scoped per addFilter call.
func (f *WindowsFirewall) permitDNSServer(ip net.IP) error {
	if v4 := ip.To4(); v4 != nil {
		var r = struct {
			addr uint32
			mask uint32
		}{addr: binary.BigEndian.Uint32(v4), mask: 0xFFFFFFFF}
		addrCond := fwpmFilterCondition0{
			fieldKey:  guidCondIPRemoteAddress,
			matchType: matchEqual,
			conditionValue: fwpConditionValue0{
				dataType: dataTypeV4Address,
				value:    uintptr(unsafe.Pointer(&r)),
			},
		}
		condsUDP := []fwpmFilterCondition0{
			{fieldKey: guidCondIPProtocol, matchType: matchEqual, conditionValue: uint8Value(17)},
			{fieldKey: guidCondIPRemotePort, matchType: matchEqual, conditionValue: uint16Value(53)},
			addrCond,
		}
		condsTCP := []fwpmFilterCondition0{
			{fieldKey: guidCondIPProtocol, matchType: matchEqual, conditionValue: uint8Value(6)},
			{fieldKey: guidCondIPRemotePort, matchType: matchEqual, conditionValue: uint16Value(53)},
			addrCond,
		}
		if _, err := f.addFilter("Permit DNS v4 UDP "+ip.String(), guidLayerAleAuthConnectV4, actionPermit, 15, condsUDP); err != nil {
			return err
		}
		if _, err := f.addFilter("Permit DNS v4 TCP "+ip.String(), guidLayerAleAuthConnectV4, actionPermit, 15, condsTCP); err != nil {
			return err
		}
		runtime.KeepAlive(&r)
		runtime.KeepAlive(condsUDP)
		runtime.KeepAlive(condsTCP)
		return nil
	}
	var addr [16]byte
	copy(addr[:], ip.To16())
	mask := [16]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	var r = struct {
		addr [16]byte
		mask [16]byte
	}{addr: addr, mask: mask}
	addrCond := fwpmFilterCondition0{
		fieldKey:  guidCondIPRemoteAddress,
		matchType: matchEqual,
		conditionValue: fwpConditionValue0{
			dataType: dataTypeV6Address,
			value:    uintptr(unsafe.Pointer(&r)),
		},
	}
	condsUDP := []fwpmFilterCondition0{
		{fieldKey: guidCondIPProtocol, matchType: matchEqual, conditionValue: uint8Value(17)},
		{fieldKey: guidCondIPRemotePort, matchType: matchEqual, conditionValue: uint16Value(53)},
		addrCond,
	}
	condsTCP := []fwpmFilterCondition0{
		{fieldKey: guidCondIPProtocol, matchType: matchEqual, conditionValue: uint8Value(6)},
		{fieldKey: guidCondIPRemotePort, matchType: matchEqual, conditionValue: uint16Value(53)},
		addrCond,
	}
	if _, err := f.addFilter("Permit DNS v6 UDP "+ip.String(), guidLayerAleAuthConnectV6, actionPermit, 15, condsUDP); err != nil {
		return err
	}
	if _, err := f.addFilter("Permit DNS v6 TCP "+ip.String(), guidLayerAleAuthConnectV6, actionPermit, 15, condsTCP); err != nil {
		return err
	}
	runtime.KeepAlive(&r)
	runtime.KeepAlive(&addr)
	runtime.KeepAlive(&mask)
	runtime.KeepAlive(condsUDP)
	runtime.KeepAlive(condsTCP)
	return nil
}

func (f *WindowsFirewall) blockAllDNS() error {
	for _, layer := range allConnectLayers {
		for _, proto := range []uint8{17, 6} {
			conds := []fwpmFilterCondition0{
				{fieldKey: guidCondIPProtocol, matchType: matchEqual, conditionValue: uint8Value(proto)},
				{fieldKey: guidCondIPRemotePort, matchType: matchEqual, conditionValue: uint16Value(53)},
			}
			if _, err := f.addFilter("Block DNS catch-all", layer, actionBlock, 14, conds); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f *WindowsFirewall) DisableDNSProtection() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// We can't remove just the DNS filters without tracking their IDs —
	// for simplicity, tear down everything and the next EnableKillSwitch
	// will rebuild. The kill switch is the more critical of the two
	// features; DNS protection toggling without an active tunnel is rare.
	if !f.killSwitchEnabled {
		f.closeSession()
		return nil
	}
	// Kill switch is up — preserving its filters means we'd need to track
	// DNS-specific IDs and delete each. TODO: when WFP filter ID tracking
	// is added, do precise removal. For now, log that DNS protection is
	// implicitly tied to the kill switch lifetime.
	f.dnsProtectionEnabled = false
	return nil
}

func (f *WindowsFirewall) IsKillSwitchEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.killSwitchEnabled
}

func (f *WindowsFirewall) IsDNSProtectionEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dnsProtectionEnabled
}

// RecoverFromCrash is a no-op on Windows: WFP filters installed in a
// dynamic session are automatically removed by the kernel when the
// creating process dies. A fresh helper starts with a clean WFP state.
func (f *WindowsFirewall) RecoverFromCrash() bool { return false }

// Cleanup tears down everything. Called from helper shutdown.
func (f *WindowsFirewall) Cleanup() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeSession()
	return nil
}
