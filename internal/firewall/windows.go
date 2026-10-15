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
	// other tunnels' filters. Keyed by interface name (which on Windows
	// is "WireGuide" today but the map is multi-tunnel-ready for the
	// per-tunnel-adapter naming change we'll need to ship later).
	tunnelFilterIDs map[string][]uint64

	// endpointProtectionFilterIDs tracks the BLOCK filters installed by
	// EnableEndpointProtection. Keyed by tunnel interface name. Separate
	// from tunnelFilterIDs so the two features have independent lifetimes
	// — toggling the kill switch off must not strip the loop protection,
	// and disconnecting one tunnel must not touch another tunnel's
	// protection set.
	endpointProtectionFilterIDs map[string][]uint64

	// endpointProtectionState remembers (iface → endpoints) for each
	// active endpoint protection install so we can re-install after a
	// dynamic-session close. Session close happens whenever the user
	// toggles the kill switch off (closeSession is the simple cascade
	// path), which would otherwise silently strip an active tunnel's
	// loop protection. The snapshot-and-rebuild pattern lets the kill
	// switch keep its tear-down-everything-rebuild simplicity while
	// preserving endpoint protection across the transition.
	endpointProtectionState map[string][]string

	// dnsFilterIDs tracks the WFP filter IDs installed by
	// EnableDNSProtection (per-server permits + the block-all-53
	// catch-all) so they can be removed precisely — on a re-enable with
	// changed servers, and on DisableDNSProtection while the kill switch
	// stays up — without tearing down the whole session.
	dnsFilterIDs []uint64
	// dnsAllow remembers the last complete (normalized) DNS permit set so
	// DisableKillSwitch (which closes and rebuilds the session) can reinstall
	// DNS protection alongside endpoint protection instead of silently
	// dropping it, and so EnableKillSwitch can re-render the installed
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
	// Closing the session cascades all filter IDs we tracked — there's no
	// per-ID delete to do, but we drop every map so a re-Enable starts
	// from a clean slate. Callers that need to PRESERVE state across a
	// session close (e.g. DisableKillSwitch snapshotting endpoint
	// protection so it can be reinstalled in a fresh session) must do
	// that snapshot themselves before calling closeSession.
	f.tunnelFilterIDs = nil
	f.endpointProtectionFilterIDs = nil
	f.endpointProtectionState = nil
	f.dnsFilterIDs = nil
	// NB: dnsAllow is intentionally NOT cleared here — DisableKillSwitch
	// closes the session and then wants to reinstall DNS protection, so it
	// needs the remembered server set to survive the cascade.
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
	var tunnelIDs, dnsIDs []uint64
	err := runWFPTransaction(f.txnOps(), "kill switch", func() error {
		if err := f.installBaseFiltersLocked(); err != nil {
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
func (f *WindowsFirewall) installBaseFiltersLocked() error {
	layers := allConnectLayers[:]

	// (1) Permit loopback — weight 13. Loopback uses LOCAL_ADDRESS, not
	// interface LUID, on these layers. Easiest match: condition on
	// remote address in 127.0.0.0/8 / ::1.
	if err := f.permitLoopback(); err != nil {
		return err
	}

	// (2) Permit DHCP IPv4 (UDP 67/68) and IPv6 (UDP 546/547) — weight 12.
	if err := f.permitDHCP(); err != nil {
		return err
	}

	// (3) Permit ICMPv6 NDP — weight 12. NDP types 133-137 are needed
	// for IPv6 router solicitation/advertisement and neighbor discovery.
	// At the ALE_AUTH_CONNECT layer we can't filter on ICMPv6 type
	// directly; we permit all ICMPv6 destined to link-local fe80::/10,
	// which covers NDP without leaking ping-of-death style abuse.
	if err := f.permitICMPv6LinkLocal(); err != nil {
		return err
	}

	// (4) Catch-all block — weight 0. Lowest priority, so per-tunnel and
	// other permits above it win. This is the actual "kill" of the
	// kill switch.
	for _, layer := range layers {
		if _, err := f.addFilter("Block all (catch-all)", layer, actionBlock, 0, nil); err != nil {
			return err
		}
	}
	return nil
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
	// place. permitEndpoint installs one filter per IP family; we
	// re-implement it inline here so we can capture the filter ID.
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
	if status := fwpmTransactionBegin0(f.sessionHandle); status != 0 {
		return fmt.Errorf("FwpmTransactionBegin0(rm-tunnel): 0x%x", status)
	}
	committed := false
	defer func() {
		if !committed {
			fwpmTransactionAbort0(f.sessionHandle)
		}
	}()
	for _, id := range ids {
		if status := fwpmFilterDeleteById0(f.sessionHandle, id); status != 0 {
			// Best-effort: log and continue. A stale ID can happen if the
			// filter was removed out-of-band (session close, manual netsh
			// wfp del); we still want to clean the rest of the slice.
			slog.Warn("RemoveKillSwitchTunnel: filter delete failed",
				"tunnel", interfaceName, "filter_id", id,
				"status", fmt.Sprintf("0x%x", status))
		}
	}
	if status := fwpmTransactionCommit0(f.sessionHandle); status != 0 {
		return fmt.Errorf("FwpmTransactionCommit0(rm-tunnel): 0x%x", status)
	}
	committed = true
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
func (f *WindowsFirewall) permitLoopback() error {
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
	_, err := f.addFilter("Permit loopback v4", guidLayerAleAuthConnectV4, actionPermit, 13, cond4)
	runtime.KeepAlive(v4)
	runtime.KeepAlive(cond4)
	if err != nil {
		return err
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
	_, err = f.addFilter("Permit loopback v6", guidLayerAleAuthConnectV6, actionPermit, 13, cond6)
	runtime.KeepAlive(v6)
	runtime.KeepAlive(cond6)
	return err
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
// See permitDNSv4 for why the address-mask struct is heap-allocated.
func (f *WindowsFirewall) permitICMPv6LinkLocal() error {
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
	_, err := f.addFilter("Permit NDP (ICMPv6 link-local)", guidLayerAleAuthConnectV6, actionPermit, 12, conds)
	runtime.KeepAlive(ll)
	runtime.KeepAlive(conds)
	return err
}

// permitEndpoint adds a single permit filter for traffic to one peer
// endpoint IP. UDP-only (WG uses UDP). See permitDNSv4 for why the
// address-mask struct is heap-allocated.
func (f *WindowsFirewall) permitEndpoint(ip net.IP) error {
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
		_, err := f.addFilter("Permit WG endpoint v4 "+ip.String(), guidLayerAleAuthConnectV4, actionPermit, 12, conds)
		runtime.KeepAlive(r)
		runtime.KeepAlive(conds)
		return err
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
	_, err := f.addFilter("Permit WG endpoint v6 "+ip.String(), guidLayerAleAuthConnectV6, actionPermit, 12, conds)
	runtime.KeepAlive(r)
	runtime.KeepAlive(conds)
	return err
}

func (f *WindowsFirewall) DisableKillSwitch() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Snapshot endpoint protection state BEFORE the session close —
	// otherwise the cascade-delete strips the loop-protection BLOCK
	// filters along with the kill switch's permits, leaving an active
	// full-tunnel connect exposed to the very loop class the protection
	// is meant to prevent.
	//
	// We deliberately rebuild rather than carrying filters across
	// sessions because WFP filter IDs are session-scoped: a fresh
	// session gets fresh IDs, so we'd need full re-registration anyway.
	//
	// There IS a microsecond-scale window between closeSession (filters
	// gone) and enableEndpointProtectionLocked (filters back) where
	// loop protection is absent. In practice a kill-switch toggle is a
	// deliberate UI action and the user is unlikely to be in the middle
	// of a routing loop at that exact moment. We accept the window
	// rather than refactor every feature set to precise ID tracking
	// (tracked as a follow-up; see DisableDNSProtection's TODO for the
	// same shape of debt).
	epSnapshot := make(map[string][]string, len(f.endpointProtectionState))
	for iface, eps := range f.endpointProtectionState {
		cp := make([]string, len(eps))
		copy(cp, eps)
		epSnapshot[iface] = cp
	}

	// Snapshot DNS protection too: closeSession cascades the DNS filters
	// away, and the kill switch and DNS protection are independent
	// toggles — if a tunnel is still connected, turning the kill switch
	// off must not silently strip DNS-leak protection.
	var dnsSnapshot []DNSAllow
	if f.dnsProtectionEnabled && len(f.dnsAllow) > 0 {
		dnsSnapshot = append([]DNSAllow(nil), f.dnsAllow...)
	}

	// Closing the dynamic session removes every filter in one shot; the
	// endpoint-protection and DNS-protection sets are reinstalled below in
	// the fresh session from the snapshots taken above.
	f.closeSession()

	// Re-install endpoint protection in a fresh session for every tunnel
	// that had it active at session-close time. Now FATAL: a silent
	// "loop protection went away" outcome left an active full-tunnel
	// exposed to the bug class this whole module exists to prevent.
	// Returning the (joined) error lets the helper surface a critical
	// event to the GUI; the user can choose to disconnect.
	var rebuildErrs []error
	for iface, eps := range epSnapshot {
		if err := f.enableEndpointProtectionLocked(iface, eps); err != nil {
			slog.Error("DisableKillSwitch: failed to reinstall endpoint protection",
				"interface", iface, "error", err)
			rebuildErrs = append(rebuildErrs,
				fmt.Errorf("reinstall endpoint protection for %s: %w", iface, err))
		}
	}
	// Reinstall DNS protection in the same fresh session if it was active.
	if len(dnsSnapshot) > 0 {
		if err := f.installDNSLocked(dnsSnapshot); err != nil {
			slog.Error("DisableKillSwitch: failed to reinstall DNS protection",
				"error", err)
			rebuildErrs = append(rebuildErrs, fmt.Errorf("reinstall DNS protection: %w", err))
		}
	}

	if len(rebuildErrs) > 0 {
		return fmt.Errorf("kill switch disabled but protection rebuild failed for %d item(s); first error: %w",
			len(rebuildErrs), rebuildErrs[0])
	}
	return nil
}

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
	servers := dnsAllowServers(effectiveDNSAllow(allow, killSwitch))
	ids := make([]uint64, 0, len(servers)*4+len(allConnectLayers)*2)
	// Permit DNS to each whitelisted server first — weight 15 (higher than
	// the block below). Both UDP and TCP, because DNS-over-TCP is a
	// legitimate fallback for >512-byte responses.
	for _, dns := range servers {
		ip := net.ParseIP(dns)
		if ip == nil {
			continue
		}
		permitIDs, err := f.permitDNSServer(ip)
		if err != nil {
			return nil, err
		}
		ids = append(ids, permitIDs...)
	}
	// Block UDP/TCP port 53 to everything else — weight 14.
	blockIDs, err := f.blockAllDNS()
	if err != nil {
		return nil, err
	}
	return append(ids, blockIDs...), nil
}

// permitDNSServer installs two filters (UDP+TCP) per address family for
// one whitelisted DNS server. Each filter is installed by an isolated
// helper that owns its own V4/V6_ADDR_MASK allocation and KeepAlives it
// the instant the syscall returns.
//
// Why the per-call isolation: an earlier version built one addrCond and
// reused it across two addFilter calls, sharing the same uintptr(&r) as
// the conditionValue. That triggered EXCEPTION_ACCESS_VIOLATION
// (0xC0000005) inside fwpuclnt.dll's FwpmFilterAdd0 on the first call
// because Go's escape analysis only sees `&r` through KeepAlive at the
// bottom of the function — it cannot trace r through a uintptr stored
// in a struct field stored in a slice. With two syscalls back-to-back
// and several local frames on stack, the goroutine had enough time for
// a stack move or GC tick to invalidate the pointer between when the
// uintptr was captured and when the kernel dereferenced it. The single
// `var r = struct{...}` / KeepAlive(&r) pattern that works for
// permitEndpoint (one filter, one syscall, tight scope) is not safe
// when the same r feeds two consecutive syscalls.
//
// The wireguard-windows reference implementation uses the same WFP
// surface but builds each filter in its own goroutine-local scope —
// mirroring that here avoids the implicit "stack frame lives long
// enough" assumption.
func (f *WindowsFirewall) permitDNSServer(ip net.IP) ([]uint64, error) {
	if v4 := ip.To4(); v4 != nil {
		udp, err := f.permitDNSv4(ip, v4, 17, "UDP")
		if err != nil {
			return nil, err
		}
		tcp, err := f.permitDNSv4(ip, v4, 6, "TCP")
		if err != nil {
			return nil, err
		}
		return []uint64{udp, tcp}, nil
	}
	var addr [16]byte
	copy(addr[:], ip.To16())
	udp, err := f.permitDNSv6(ip, addr, 17, "UDP")
	if err != nil {
		return nil, err
	}
	tcp, err := f.permitDNSv6(ip, addr, 6, "TCP")
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
func (f *WindowsFirewall) permitDNSv4(ip net.IP, v4 net.IP, proto uint8, protoName string) (uint64, error) {
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
	id, err := f.addFilter("Permit DNS v4 "+protoName+" "+ip.String(), guidLayerAleAuthConnectV4, actionPermit, 15, conds)
	runtime.KeepAlive(r)
	runtime.KeepAlive(conds)
	return id, err
}

// permitDNSv6 mirrors permitDNSv4 for IPv6 — single filter, heap-
// allocated V6_ADDR_MASK, KeepAlive immediately after the syscall.
func (f *WindowsFirewall) permitDNSv6(ip net.IP, addr [16]byte, proto uint8, protoName string) (uint64, error) {
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
	id, err := f.addFilter("Permit DNS v6 "+protoName+" "+ip.String(), guidLayerAleAuthConnectV6, actionPermit, 15, conds)
	runtime.KeepAlive(r)
	runtime.KeepAlive(conds)
	return id, err
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
