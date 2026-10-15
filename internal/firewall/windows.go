//go:build windows

package firewall

import (
	"encoding/binary"
	"fmt"
	"log/slog"
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

	// tunnelFilterIDs tracks per-tunnel WFP filter IDs installed by
	// AddKillSwitchTunnel so RemoveKillSwitchTunnel can delete only that
	// tunnel's filters without disturbing the base catch-all set or
	// other tunnels' filters. Each tunnel has its own adapter name.
	tunnelFilterIDs map[string][]uint64
	baseFilterIDs   []uint64 // kill-switch-only permits and catch-all blocks

	// endpointProtectionFilterIDs tracks the BLOCK filters installed by
	// EnableEndpointProtection. Keyed by tunnel interface name. Separate
	// from tunnelFilterIDs so the two features have independent lifetimes
	// — toggling the kill switch off must not strip the loop protection,
	// and disconnecting one tunnel must not touch another tunnel's
	// protection set.
	endpointProtectionFilterIDs map[string][]uint64

	// endpointProtectionState records the endpoints protected on each
	// interface. It changes only after the corresponding WFP commit.
	endpointProtectionState map[string][]string

	// dnsFilterIDs tracks the WFP filter IDs installed by
	// EnableDNSProtection (per-server permits + the block-all-53
	// catch-all) so they can be removed precisely — on a re-enable with
	// changed servers, and on DisableDNSProtection while the kill switch
	// stays up — without tearing down the whole session.
	dnsFilterIDs []uint64
	// dnsAllow remembers the last complete (normalized) DNS permit set so
	// kill-switch transitions can re-render the installed
	// permits for kill-switch mode (see effectiveDNSAllow).
	dnsAllow []DNSAllow
}

func NewPlatformFirewall() FirewallManager {
	// Best-effort: nuke any sublayer + filters our fixed GUIDs left
	// behind on a previous helper run that didn't shut down cleanly.
	// Without this, a leaked dynamic session that the kernel somehow
	// didn't reclaim survives a helper restart, and the user's only
	// recovery is a reboot. SweepOrphanedFilters is no-op on a clean
	// machine (FWP_E_NOT_FOUND, silently ignored).
	SweepOrphanedFilters()
	return &WindowsFirewall{}
}

// wireguideProviderKey / wireguideSublayerKey are FIXED GUIDs used by
// every helper instance. Two consequences:
//
//  1. SweepOrphanedFilters on startup can cascade-delete the sublayer
//     by these known GUIDs, wiping any leftover filters from a previous
//     helper run that failed to close its dynamic session cleanly. The
//     previous random-per-session GUIDs made that impossible — once
//     leaked, the only recovery was reboot.
//
//  2. Two simultaneous helpers will collide on add. We don't support
//     concurrent helpers anyway (the IPC pipe is single-instance), so
//     this is the right trade-off: deterministic recovery beats
//     defending against a use case that already errors out elsewhere.
//
// Values were generated once with `[guid]::NewGuid()`; nothing about
// them is sensitive — they only need to be unique within WFP's GUID
// namespace.
var (
	wireguideProviderKey = windows.GUID{
		Data1: 0x9b3d7a52, Data2: 0xf8c4, Data3: 0x4a91,
		Data4: [8]byte{0xb1, 0x6e, 0x2c, 0x8d, 0x4f, 0x5a, 0x6b, 0x71},
	}
	wireguideSublayerKey = windows.GUID{
		Data1: 0x9b3d7a53, Data2: 0xf8c4, Data3: 0x4a91,
		Data4: [8]byte{0xb1, 0x6e, 0x2c, 0x8d, 0x4f, 0x5a, 0x6b, 0x72},
	}
)

// SweepOrphanedFilters opens a one-shot non-dynamic WFP session and
// asks the kernel to delete our sublayer (and, by cascade, every filter
// attached to it) plus the provider. Called once at helper startup
// before ensureSession installs a fresh dynamic session.
//
// All errors are best-effort: FWP_E_NOT_FOUND is the expected state on
// a clean machine and we don't need to distinguish it. A non-zero
// status is logged but never blocks startup — the new dynamic session
// will simply fail to add the provider/sublayer if cleanup missed,
// which surfaces as a louder error than a silent leak.
func SweepOrphanedFilters() {
	displayName := utf16Ptr("WireGuide-Sweeper")
	sess := fwpmSession0{
		displayData:          fwpmDisplayData0{name: displayName},
		txnWaitTimeoutInMSec: 0xFFFFFFFF,
	}
	var handle uintptr
	if status := fwpmEngineOpen0(&sess, &handle); status != 0 {
		slog.Warn("WFP SweepOrphanedFilters: engine open failed",
			"status", fmt.Sprintf("0x%x", status))
		return
	}
	defer fwpmEngineClose0(handle)

	subKey := wireguideSublayerKey
	if status := fwpmSubLayerDeleteByKey0(handle, &subKey); status != 0 {
		const fwpENotFound uint32 = 0x80320008
		if status != fwpENotFound {
			slog.Info("WFP SweepOrphanedFilters: sublayer delete reported status",
				"status", fmt.Sprintf("0x%x", status))
		}
	} else {
		slog.Info("WFP SweepOrphanedFilters: removed orphaned sublayer + filters from a previous run")
	}

	provKey := wireguideProviderKey
	if status := fwpmProviderDeleteByKey0(handle, &provKey); status != 0 {
		const fwpENotFound uint32 = 0x80320008
		if status != fwpENotFound {
			slog.Info("WFP SweepOrphanedFilters: provider delete reported status",
				"status", fmt.Sprintf("0x%x", status))
		}
	}
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

	providerKey := wireguideProviderKey
	sublayerKey := wireguideSublayerKey

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
//
// We log the FwpmEngineClose0 status because a non-zero return means the
// kernel didn't actually destroy the session — and with the session
// alive, every filter we added stays in force. A previous user-reported
// outage ("disabled kill switch, internet still blocked, had to reboot")
// matches that failure mode exactly. If you see this log, the only
// reliable recovery short of reboot is killing the helper PID with
// elevated rights (kernel auto-cleans dynamic sessions on process
// death) — netsh wfp del filter by hand would otherwise have to walk
// the whole provider list.
func (f *WindowsFirewall) closeSession() {
	if f.sessionHandle == 0 {
		return
	}
	if status := fwpmEngineClose0(f.sessionHandle); status != 0 {
		slog.Error("WFP FwpmEngineClose0 failed — filters may remain installed; killing the helper PID is the safest recovery",
			"status", fmt.Sprintf("0x%x", status),
			"session_handle", f.sessionHandle)
	}
	f.sessionHandle = 0
	f.killSwitchEnabled = false
	f.dnsProtectionEnabled = false
	f.baseFilterIDs = nil
	f.tunnelFilterIDs = nil
	f.endpointProtectionFilterIDs = nil
	f.endpointProtectionState = nil
	f.dnsFilterIDs = nil
	f.dnsAllow = nil
}

// procConvertAliasToLuidFW is the package-level iphlpapi handle used by
// resolveInterfaceLUID. Lazy-bound at first call; subsequent calls reuse
// the resolved address. Previously we re-resolved on every Enable*
// (every connect path) — measurable but small win to lift here.
var procConvertAliasToLuidFW = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("ConvertInterfaceAliasToLuid")

// resolveInterfaceLUID looks up the LUID of the tunnel interface by its
// friendly name (as wintun creates it). The LUID is what WFP filters key
// on — interface index would also work but LUIDs are stable across
// re-creation, which matters for crash recovery.
//
// We do NOT pre-check existence via net.Interfaces() before calling
// ConvertInterfaceAliasToLuid: the iphlpapi call is itself the canonical
// "does this alias exist" oracle (returns ERROR_NOT_FOUND), and the
// pre-check syscall + slice allocation was pure overhead on every
// EnableEndpointProtection.
var resolveInterfaceLUID = func(ifaceName string) (uint64, error) {
	if ifaceName == "" {
		return 0, fmt.Errorf("resolveInterfaceLUID: empty alias")
	}
	u16, err := windows.UTF16PtrFromString(ifaceName)
	if err != nil {
		return 0, err
	}
	var luid uint64
	ret, _, _ := procConvertAliasToLuidFW.Call(
		uintptr(unsafe.Pointer(u16)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("ConvertInterfaceAliasToLuid(%q): 0x%x", ifaceName, ret)
	}
	return luid, nil
}

// addFilter installs one filter. Conditions are passed as a slice; the
// kernel copies them out synchronously during FwpmFilterAdd0, so we only
// need to keep them alive across the syscall. runtime.KeepAlive is
// mandatory because uintptr(unsafe.Pointer(&v)) drops the GC tracking
// reference — without it the compiler may free the backing memory
// while the syscall is still reading it.
func (f *WindowsFirewall) addFilter(name string, layerKey windows.GUID, action uint32, weight uint8, conditions []fwpmFilterCondition0) (uint64, error) {
	displayName := utf16Ptr(name)
	filter := fwpmFilter0{
		displayData:         fwpmDisplayData0{name: displayName},
		flags:               fwpmFilterFlagNone,
		providerKey:         &f.providerKey,
		layerKey:            layerKey,
		subLayerKey:         f.sublayerKey,
		weight:              filterWeight(weight),
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

// EnableKillSwitch installs the base WFP filter set (loopback / DHCP /
// NDP / catch-all block). When interfaceName is non-empty it also
// installs the per-tunnel permits (Permit tunnel LUID + Permit each peer
// endpoint outbound) so a connect happening alongside enable is covered
// in one transaction; when interfaceName is empty the kill switch turns
// on immediately with no tunnel, blocking everything until the user
// either connects a tunnel (handled by AddKillSwitchTunnel) or toggles
// the switch back off.
//
// Idempotent: calling Enable again while killSwitchEnabled is true is a
// no-op so the GUI's "auto-apply on connect" flow can fire freely.
//
// ifaceAddresses is accepted for cross-platform parity but unused on
// Windows — the per-tunnel LUID permit covers the same role.
func (f *WindowsFirewall) EnableKillSwitch(interfaceName string, _ []string, endpoints []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.killSwitchEnabled {
		// Already on — if a tunnel arrived at the same time, fold its
		// permits in without re-installing the base set. This is the
		// "user toggled kill switch on first, then connected" sequence.
		if interfaceName != "" {
			return f.addTunnelFiltersLocked(interfaceName, endpoints)
		}
		return nil
	}
	if err := f.ensureSession(); err != nil {
		return err
	}

	// DNS permits outrank the catch-all block (weight 15 > 0) and are not
	// bound to an interface, so an installed off-tunnel resolver permit would
	// be an exception to the kill switch. The base set, the tunnel permits
	// and the DNS set narrowed for kill-switch mode commit together: if the
	// narrowing fails, nothing commits and the kill switch is not reported
	// enabled with the old exception still in force.
	narrowDNS := f.dnsProtectionEnabled && len(f.dnsAllow) > 0
	var baseIDs, tunnelIDs, dnsIDs []uint64
	err := runWFPTransaction(f.txnOps(), "kill switch", func() error {
		var err error
		baseIDs, err = f.installBaseFiltersLocked()
		if err != nil {
			return err
		}
		if interfaceName != "" {
			ids, err := f.installTunnelFiltersLocked(interfaceName, endpoints)
			if err != nil {
				return err
			}
			tunnelIDs = ids
		}
		if narrowDNS {
			ids, err := f.renderDNSFiltersLocked(f.dnsAllow, true)
			if err != nil {
				return fmt.Errorf("narrow DNS permits for kill switch: %w", err)
			}
			dnsIDs = ids
		}
		return nil
	})
	if err != nil {
		return err
	}
	f.killSwitchEnabled = true
	f.baseFilterIDs = baseIDs
	if interfaceName != "" {
		f.recordTunnelFiltersLocked(interfaceName, tunnelIDs)
	}
	if narrowDNS {
		f.dnsFilterIDs = dnsIDs
	}
	return nil
}

// installBaseFiltersLocked installs the VPN-independent permits and the
// catch-all block. Caller MUST hold f.mu AND must be inside a WFP
// transaction.
func (f *WindowsFirewall) installBaseFiltersLocked() ([]uint64, error) {
	ids, err := f.permitLoopback()
	if err != nil {
		return nil, err
	}
	dhcp, err := f.permitDHCP()
	if err != nil {
		return nil, err
	}
	ids = append(ids, dhcp...)
	ndp, err := f.permitICMPv6LinkLocal()
	if err != nil {
		return nil, err
	}
	ids = append(ids, ndp)
	for _, layer := range allConnectLayers {
		id, err := f.addFilter("Block all (catch-all)", layer, actionBlock, 0, nil)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// installTunnelFiltersLocked installs Permit-tunnel-LUID and
// Permit-endpoint filters for one tunnel and returns their IDs. The caller
// records them (recordTunnelFiltersLocked) after its commit so
// RemoveKillSwitchTunnel can pull the same set out later. Caller MUST hold
// f.mu AND must be inside a WFP transaction.
func (f *WindowsFirewall) installTunnelFiltersLocked(interfaceName string, endpoints []string) ([]uint64, error) {
	luid, err := resolveInterfaceLUID(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("resolve tunnel LUID: %w", err)
	}
	var ids []uint64

	// Permit on tunnel interface — weight 12. One per ALE layer (v4+v6).
	for _, layer := range allConnectLayers {
		luidCopy := luid
		conds := []fwpmFilterCondition0{
			{
				fieldKey:       guidCondIPLocalInterface,
				matchType:      matchEqual,
				conditionValue: uint64ValuePtr(&luidCopy),
			},
		}
		id, err := f.addFilter("Permit tunnel", layer, actionPermit, 12, conds)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
		runtime.KeepAlive(&luidCopy)
		runtime.KeepAlive(conds)
	}

	// Permit each WG endpoint IP outbound — weight 12. Lets the
	// encrypted WG packets reach the server even with the catch-all in
	// place. Track these separately from the base catch-all rules.
	for _, ep := range endpoints {
		ipStr, _, _ := net.SplitHostPort(ep)
		if ipStr == "" {
			ipStr = ep
		}
		parsed := net.ParseIP(ipStr)
		if parsed == nil {
			continue
		}
		id, err := f.addEndpointFilterLocked(parsed)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// recordTunnelFiltersLocked tracks a tunnel's permits after their
// transaction committed. An aborted transaction must record nothing: a
// tracked-but-absent permit makes addTunnelFiltersLocked skip the tunnel and
// leaves it blocked by the kill switch. Caller MUST hold f.mu.
func (f *WindowsFirewall) recordTunnelFiltersLocked(interfaceName string, ids []uint64) {
	if f.tunnelFilterIDs == nil {
		f.tunnelFilterIDs = make(map[string][]uint64, 1)
	}
	f.tunnelFilterIDs[interfaceName] = ids
}

// addTunnelFiltersLocked wraps installTunnelFiltersLocked in its own
// transaction for callers (AddKillSwitchTunnel) that arrive after the
// kill switch is already enabled. Caller MUST hold f.mu.
func (f *WindowsFirewall) addTunnelFiltersLocked(interfaceName string, endpoints []string) error {
	if len(f.tunnelFilterIDs[interfaceName]) > 0 {
		return nil
	}
	var ids []uint64
	err := runWFPTransaction(f.txnOps(), "add-tunnel", func() error {
		var err error
		ids, err = f.installTunnelFiltersLocked(interfaceName, endpoints)
		return err
	})
	if err != nil {
		return err
	}
	f.recordTunnelFiltersLocked(interfaceName, ids)
	return nil
}

// addEndpointFilterLocked installs one Permit-endpoint filter (UDP to a
// single peer IP /32 or /128) and returns its WFP filter ID. Inline
// version of permitEndpoint that surfaces the ID so the caller can
// register it for per-tunnel removal. Caller MUST hold f.mu AND must be
// inside a WFP transaction.
func (f *WindowsFirewall) addEndpointFilterLocked(ip net.IP) (uint64, error) {
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
		}
		id, err := f.addFilter("Permit WG endpoint v4 "+ip.String(), guidLayerAleAuthConnectV4, actionPermit, 12, conds)
		runtime.KeepAlive(r)
		runtime.KeepAlive(conds)
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
	}
	id, err := f.addFilter("Permit WG endpoint v6 "+ip.String(), guidLayerAleAuthConnectV6, actionPermit, 12, conds)
	runtime.KeepAlive(r)
	runtime.KeepAlive(conds)
	return id, err
}

// AddKillSwitchTunnel installs Permit-tunnel + Permit-endpoint filters
// for one tunnel into the active kill-switch filter set. No-op if the
// kill switch isn't enabled. Safe to call multiple times for the same
// name (an existing tracked set is left unchanged).
func (f *WindowsFirewall) AddKillSwitchTunnel(interfaceName string, _ []string, endpoints []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.killSwitchEnabled {
		return nil
	}
	if interfaceName == "" {
		return fmt.Errorf("AddKillSwitchTunnel: empty interface name")
	}
	return f.addTunnelFiltersLocked(interfaceName, endpoints)
}

// RemoveKillSwitchTunnel deletes the per-tunnel filters installed by
// AddKillSwitchTunnel (or by EnableKillSwitch's initial install) for
// one tunnel. The catch-all base set stays in place — the user still
// has the kill switch on. No-op if the tunnel has no tracked filters.
func (f *WindowsFirewall) RemoveKillSwitchTunnel(interfaceName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.killSwitchEnabled || f.sessionHandle == 0 {
		return nil
	}
	ids := f.tunnelFilterIDs[interfaceName]
	if len(ids) == 0 {
		return nil
	}
	if err := runWFPTransaction(f.txnOps(), "rm-tunnel", func() error {
		return deleteWFPFilters(f.deleteFilter, ids, "tunnel")
	}); err != nil {
		return err
	}
	delete(f.tunnelFilterIDs, interfaceName)
	return nil
}

// permitLoopback permits outbound to 127.0.0.0/8 (IPv4) and ::1/128 (IPv6).
// Implemented as two conditions per layer matching remote address ranges.
//
// Loopback connections at the ALE layer don't typically need an explicit
// permit because Windows treats loopback specially, but we add it for
// belt-and-suspenders compatibility with apps that bind explicit loopback
// sockets.
//
// V4_ADDR_MASK / V6_ADDR_MASK structs are heap-allocated and the Go
// pointer is held in a stack slot — see permitDNSv4 for the rationale
// on why the older `var r = struct{...}; uintptr(unsafe.Pointer(&r))`
// pattern is unsafe across a WFP syscall (escape analysis can't trace
// r through a uintptr in a struct field).
func (f *WindowsFirewall) permitLoopback() ([]uint64, error) {
	// IPv4 loopback /8: address 127.0.0.0, mask 255.0.0.0.
	v4 := &fwpV4AddrMask{addr: 0x7F000000, mask: 0xFF000000}
	cond4 := []fwpmFilterCondition0{
		{
			fieldKey:  guidCondIPRemoteAddress,
			matchType: matchEqual,
			conditionValue: fwpConditionValue0{
				dataType: dataTypeV4Address,
				value:    uintptr(unsafe.Pointer(v4)),
			},
		},
	}
	id4, err := f.addFilter("Permit loopback v4", guidLayerAleAuthConnectV4, actionPermit, 13, cond4)
	runtime.KeepAlive(v4)
	runtime.KeepAlive(cond4)
	if err != nil {
		return nil, err
	}

	// IPv6 loopback ::1/128.
	v6 := &fwpV6AddrMask{
		addr:         [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		prefixLength: 128,
	}
	cond6 := []fwpmFilterCondition0{
		{
			fieldKey:  guidCondIPRemoteAddress,
			matchType: matchEqual,
			conditionValue: fwpConditionValue0{
				dataType: dataTypeV6Address,
				value:    uintptr(unsafe.Pointer(v6)),
			},
		},
	}
	id6, err := f.addFilter("Permit loopback v6", guidLayerAleAuthConnectV6, actionPermit, 13, cond6)
	runtime.KeepAlive(v6)
	runtime.KeepAlive(cond6)
	return []uint64{id4, id6}, err
}

// permitDHCP permits UDP 67/68 (IPv4 DHCP) and UDP 546/547 (IPv6 DHCPv6).
func (f *WindowsFirewall) permitDHCP() ([]uint64, error) {
	// IPv4 DHCP: UDP, local port 68, remote port 67.
	v4Conds := []fwpmFilterCondition0{
		{fieldKey: guidCondIPProtocol, matchType: matchEqual, conditionValue: uint8Value(17)},
		{fieldKey: guidCondIPLocalPort, matchType: matchEqual, conditionValue: uint16Value(68)},
		{fieldKey: guidCondIPRemotePort, matchType: matchEqual, conditionValue: uint16Value(67)},
	}
	id4, err := f.addFilter("Permit DHCPv4", guidLayerAleAuthConnectV4, actionPermit, 12, v4Conds)
	if err != nil {
		return nil, err
	}

	// IPv6 DHCPv6: UDP, local port 546, remote port 547.
	v6Conds := []fwpmFilterCondition0{
		{fieldKey: guidCondIPProtocol, matchType: matchEqual, conditionValue: uint8Value(17)},
		{fieldKey: guidCondIPLocalPort, matchType: matchEqual, conditionValue: uint16Value(546)},
		{fieldKey: guidCondIPRemotePort, matchType: matchEqual, conditionValue: uint16Value(547)},
	}
	id6, err := f.addFilter("Permit DHCPv6", guidLayerAleAuthConnectV6, actionPermit, 12, v6Conds)
	return []uint64{id4, id6}, err
}

// permitICMPv6LinkLocal permits ICMPv6 (protocol 58) to fe80::/10.
// See permitDNSv4 for why the address-mask struct is heap-allocated.
func (f *WindowsFirewall) permitICMPv6LinkLocal() (uint64, error) {
	// fe80::/10 — IPv6 link-local prefix.
	ll := &fwpV6AddrMask{
		addr:         [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		prefixLength: 10,
	}
	conds := []fwpmFilterCondition0{
		{fieldKey: guidCondIPProtocol, matchType: matchEqual, conditionValue: uint8Value(58)},
		{
			fieldKey:  guidCondIPRemoteAddress,
			matchType: matchEqual,
			conditionValue: fwpConditionValue0{
				dataType: dataTypeV6Address,
				value:    uintptr(unsafe.Pointer(ll)),
			},
		},
	}
	id, err := f.addFilter("Permit NDP (ICMPv6 link-local)", guidLayerAleAuthConnectV6, actionPermit, 12, conds)
	runtime.KeepAlive(ll)
	runtime.KeepAlive(conds)
	return id, err
}

func (f *WindowsFirewall) DisableKillSwitch() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.killSwitchEnabled {
		return nil
	}

	// Remove only this feature's filters. Closing the shared dynamic
	// session would also remove endpoint and DNS protection, leaving a gap
	// while they were rebuilt. DNS permits widen in the same transaction.
	var dnsIDs []uint64
	err := runWFPTransaction(f.txnOps(), "disable kill switch", func() error {
		if err := deleteWFPFilters(f.deleteFilter, f.baseFilterIDs, "kill-switch base"); err != nil {
			return err
		}
		for _, ids := range f.tunnelFilterIDs {
			if err := deleteWFPFilters(f.deleteFilter, ids, "kill-switch tunnel"); err != nil {
				return err
			}
		}
		if f.dnsProtectionEnabled {
			var err error
			dnsIDs, err = f.renderDNSFiltersLocked(f.dnsAllow, false)
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	f.killSwitchEnabled = false
	f.baseFilterIDs = nil
	f.tunnelFilterIDs = nil
	if f.dnsProtectionEnabled {
		f.dnsFilterIDs = dnsIDs
	}
	if f.sessionIdleLocked() {
		f.closeSession()
	}
	return nil
}

// fwpV4AddrMask mirrors FWP_V4_ADDR_AND_MASK: addr + mask, both UINT32
// in host byte order, total 8 bytes.
type fwpV4AddrMask struct {
	addr uint32
	mask uint32
}

// fwpV6AddrMask mirrors FWP_V6_ADDR_AND_MASK from fwptypes.h: 16 bytes
// of address followed by a SINGLE prefix-length byte (NOT a 16-byte
// mask like the v4 variant). A previous version used a 16-byte mask
// here; the kernel read mask[0] (0xff) as prefixLength=255, which is
// invalid for IPv6 (max 128) and surfaced as
// FWP_E_INCOMPATIBLE_LAYER (0x8032001f) the first time the kill switch
// installed a loopback-v6 filter.
//
// Total size 17 bytes; no Go alignment padding is needed because
// uint8 has alignment 1.
type fwpV6AddrMask struct {
	addr         [16]byte
	prefixLength uint8
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
