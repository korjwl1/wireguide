//go:build windows

package network

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// adapterBufSize is the fixed scratch-buffer size we pool for
// GetAdaptersAddresses. 16KB fits the typical machine (a few network
// adapters, a few DNS servers each). Anything larger gets a one-shot
// heap allocation in callGetAdaptersAddresses below — those grown buffers
// are NOT returned to the pool, keeping the pool's memory footprint
// bounded.
const adapterBufSize = 16384

// adapterBufPool reuses the 16KB scratch buffer that GetAdaptersAddresses
// writes into. Without pooling we'd allocate (and immediately discard)
// ~16KB on every getDefaultRoute / getDNSServersForInterface call — and
// these are called multiple times per Connect (default-route lookup +
// MTU + DNS save + DNS query for restore).
//
// The pool returns *[adapterBufSize]byte (pointer to fixed-size array)
// rather than *[]byte so future maintainers can't accidentally reslice
// the buffer and contaminate the pool with a wrong-sized backing array.
var adapterBufPool = sync.Pool{
	New: func() any {
		var b [adapterBufSize]byte
		return &b
	},
}

// iphlpapi bindings used to replace PowerShell calls. Each PowerShell cold
// start is 500ms-2s; on a busy network the helper would spend several
// seconds inside Get-NetRoute / Get-DnsClientServerAddress every Connect.
// Direct API calls cost microseconds and never spawn a subprocess.

var (
	modIphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procGetIpForwardTable2          = modIphlpapi.NewProc("GetIpForwardTable2")
	procGetAdaptersAddresses        = modIphlpapi.NewProc("GetAdaptersAddresses")
	procGetIpInterfaceEntry         = modIphlpapi.NewProc("GetIpInterfaceEntry")
	procFreeMibTable                = modIphlpapi.NewProc("FreeMibTable")
	procConvertInterfaceLuidToIndex = modIphlpapi.NewProc("ConvertInterfaceLuidToIndex")
	procConvertInterfaceAliasToLuid = modIphlpapi.NewProc("ConvertInterfaceAliasToLuid")
)

// Constants from netioapi.h / iphlpapi.h
const (
	afUnspec = 0
	afInet   = 2
	afInet6  = 23

	// GetAdaptersAddresses flags
	gaaFlagSkipUnicast    = 0x0001
	gaaFlagSkipAnycast    = 0x0002
	gaaFlagSkipMulticast  = 0x0004
	gaaFlagSkipDNSServer  = 0x0080
	gaaFlagIncludeGateways = 0x0080 // GAA_FLAG_INCLUDE_GATEWAYS
)

// mibIpforwardRow2 is netioapi.h MIB_IPFORWARD_ROW2 (partial — only fields
// we read). Sizes carefully match the C struct because the kernel writes
// directly into our buffer.
type mibIpforwardRow2 struct {
	InterfaceLuid       uint64
	InterfaceIndex      uint32
	DestinationPrefix   mibIpAddressPrefix
	NextHop             sockaddrInet
	SitePrefixLength    uint8
	ValidLifetime       uint32
	PreferredLifetime   uint32
	Metric              uint32
	Protocol            uint32
	Loopback            uint8
	AutoconfigureAddress uint8
	Publish             uint8
	Immortal            uint8
	Age                 uint32
	Origin              uint32
}

type mibIpAddressPrefix struct {
	Prefix       sockaddrInet
	PrefixLength uint8
	_pad         [3]byte
}

// sockaddrInet is the SOCKADDR_INET union — 28 bytes large enough for either
// SOCKADDR_IN or SOCKADDR_IN6. We pull family from the first 2 bytes and
// extract the address bytes manually.
type sockaddrInet struct {
	raw [28]byte
}

func (s *sockaddrInet) family() uint16 {
	return *(*uint16)(unsafe.Pointer(&s.raw[0]))
}

// ip returns the address as net.IP. Returns nil on unknown family.
func (s *sockaddrInet) ip() net.IP {
	switch s.family() {
	case afInet:
		// SOCKADDR_IN: family(2) + port(2) + addr(4) + zero(8)
		return net.IPv4(s.raw[4], s.raw[5], s.raw[6], s.raw[7])
	case afInet6:
		// SOCKADDR_IN6: family(2) + port(2) + flowinfo(4) + addr(16) + scope(4)
		ip := make(net.IP, 16)
		copy(ip, s.raw[8:24])
		return ip
	}
	return nil
}

type mibIpforwardTable2 struct {
	NumEntries uint32
	_pad       [4]byte
	// Followed by NumEntries * mibIpforwardRow2.
}

// freeMibTable releases a buffer allocated by GetIpForwardTable2 /
// GetIfTable2 / similar. Safe on nil.
func freeMibTable(ptr unsafe.Pointer) {
	if ptr == nil {
		return
	}
	procFreeMibTable.Call(uintptr(ptr))
}

// defaultRouteInfo holds the relevant fields of the lowest-metric default
// route for one address family.
type defaultRouteInfo struct {
	NextHop        net.IP
	InterfaceIndex uint32
	InterfaceLuid  uint64
	Metric         uint32
}

// getDefaultRoute returns the lowest-metric default route for the given
// address family (afInet or afInet6). Returns nil if no default route is
// installed (e.g. fresh boot before DHCP completes).
func getDefaultRoute(family uint32) *defaultRouteInfo {
	return getDefaultRouteFiltered(family, nil)
}

// getDefaultRouteFiltered returns the lowest-metric default route for the
// given family, skipping any route whose interface LUID is excluded by
// the predicate. Passing nil for excluded matches every interface (same
// behaviour as getDefaultRoute).
//
// Used by the reconnect detector to find "the upstream interface" — i.e.
// the best default route that ISN'T our own VPN adapter. Without this
// filter, bringing up a full-tunnel WireGuard interface would itself
// look like a network change (the WireGuard adapter becomes the lowest-
// metric default route), triggering an immediate reconnect → tear-down →
// re-create loop.
func getDefaultRouteFiltered(family uint32, excluded func(luid uint64) bool) *defaultRouteInfo {
	var tablePtr unsafe.Pointer
	ret, _, _ := procGetIpForwardTable2.Call(uintptr(family), uintptr(unsafe.Pointer(&tablePtr)))
	if ret != 0 || tablePtr == nil {
		return nil
	}
	defer freeMibTable(tablePtr)

	hdr := (*mibIpforwardTable2)(tablePtr)
	n := int(hdr.NumEntries)
	if n == 0 {
		return nil
	}
	// Rows immediately follow the header. Use unsafe pointer arithmetic.
	rowsBase := unsafe.Pointer(uintptr(tablePtr) + unsafe.Sizeof(mibIpforwardTable2{}))
	rowSize := unsafe.Sizeof(mibIpforwardRow2{})

	var best *defaultRouteInfo
	for i := 0; i < n; i++ {
		row := (*mibIpforwardRow2)(unsafe.Pointer(uintptr(rowsBase) + uintptr(i)*rowSize))
		if row.DestinationPrefix.PrefixLength != 0 {
			continue // not a default route
		}
		// PrefixLength==0 + family matches → this is the IPv4 0.0.0.0/0 or
		// IPv6 ::/0 default route.
		if row.DestinationPrefix.Prefix.family() != uint16(family) {
			continue
		}
		nh := row.NextHop.ip()
		if nh == nil || nh.IsUnspecified() {
			continue
		}
		// Loopback routes are skipped; we only want the real default.
		if row.Loopback != 0 {
			continue
		}
		if excluded != nil && excluded(row.InterfaceLuid) {
			continue
		}
		cand := defaultRouteInfo{
			NextHop:        nh,
			InterfaceIndex: row.InterfaceIndex,
			InterfaceLuid:  row.InterfaceLuid,
			Metric:         row.Metric,
		}
		if best == nil || cand.Metric < best.Metric {
			tmp := cand
			best = &tmp
		}
	}
	return best
}

// convertInterfaceAliasToLuid resolves a Windows adapter alias (the
// "FriendlyName" you see in Network Connections, e.g. "WireGuide" or
// "Wi-Fi") to its NET_LUID. Returns 0, false if the adapter does not
// exist — which is the expected case before the first Connect, and
// after Disconnect.
func convertInterfaceAliasToLuid(alias string) (uint64, bool) {
	if alias == "" {
		return 0, false
	}
	u16, err := windows.UTF16PtrFromString(alias)
	if err != nil {
		return 0, false
	}
	var luid uint64
	ret, _, _ := procConvertInterfaceAliasToLuid.Call(
		uintptr(unsafe.Pointer(u16)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if ret != 0 {
		return 0, false
	}
	return luid, true
}

// WindowsRouteEntry is one row of the IPv4 routing table, with the
// interface LUID resolved to a friendly name (e.g. "WireGuide",
// "이더넷 3"). The Diagnostics → Routes view consumes this directly.
type WindowsRouteEntry struct {
	Destination   string // CIDR ("0.0.0.0/1") or "0.0.0.0" for default
	Gateway       string // "On-link" when next-hop is the interface itself, else dotted-IP
	Interface     string // FriendlyName from GetAdaptersAddresses; falls back to "if#N"
	Metric        uint32 // route metric (lower = preferred)
	InterfaceLuid uint64 // raw NET_LUID — useful for filtering UI-side
}

// EnumerateIPv4Routes returns every active IPv4 route the kernel knows
// about, source-of-truth via iphlpapi's GetIpForwardTable2 — same API
// Get-NetRoute uses. Replaces a previous `route print -4` parser that
// silently returned empty results on this machine (the precise reason
// was never pinned down — likely the GUI-side exec ran into an
// environment quirk that `route.exe` didn't tolerate, or its output
// changed shape mid-line in a way the field-count check skipped). The
// iphlpapi path also avoids spawning a console child (no conhost
// flash) and is locale-independent.
//
// Returns nil on syscall failure; callers should treat that as "table
// unavailable" rather than empty.
func EnumerateIPv4Routes() []WindowsRouteEntry {
	var tablePtr unsafe.Pointer
	ret, _, _ := procGetIpForwardTable2.Call(uintptr(afInet), uintptr(unsafe.Pointer(&tablePtr)))
	if ret != 0 || tablePtr == nil {
		return nil
	}
	defer freeMibTable(tablePtr)

	hdr := (*mibIpforwardTable2)(tablePtr)
	n := int(hdr.NumEntries)
	if n == 0 {
		return nil
	}

	// Resolve interface index → FriendlyName once for every adapter the
	// kernel currently knows about; avoids one GetAdaptersAddresses
	// round-trip per row when the table has dozens of entries (typical
	// machine with a tunnel up easily hits 20+).
	ifNames := snapshotInterfaceNames()

	rowsBase := unsafe.Pointer(uintptr(tablePtr) + unsafe.Sizeof(mibIpforwardTable2{}))
	rowSize := unsafe.Sizeof(mibIpforwardRow2{})

	out := make([]WindowsRouteEntry, 0, n)
	for i := 0; i < n; i++ {
		row := (*mibIpforwardRow2)(unsafe.Pointer(uintptr(rowsBase) + uintptr(i)*rowSize))
		fam := row.DestinationPrefix.Prefix.family()
		if fam != uint16(afInet) {
			continue
		}
		destIP := row.DestinationPrefix.Prefix.ip()
		if destIP == nil {
			continue
		}
		dest := destIP.String()
		if row.DestinationPrefix.PrefixLength != 32 {
			dest = fmt.Sprintf("%s/%d", dest, row.DestinationPrefix.PrefixLength)
		}
		nh := row.NextHop.ip()
		gw := "On-link"
		if nh != nil && !nh.IsUnspecified() {
			gw = nh.String()
		}
		ifName := ifNames[row.InterfaceIndex]
		if ifName == "" {
			ifName = "if#" + strconvU32(row.InterfaceIndex)
		}
		out = append(out, WindowsRouteEntry{
			Destination:   dest,
			Gateway:       gw,
			Interface:     ifName,
			Metric:        row.Metric,
			InterfaceLuid: row.InterfaceLuid,
		})
	}
	return out
}

// snapshotInterfaceNames returns a map of Windows interface index →
// adapter FriendlyName. Empty map on lookup failure (caller falls back
// to "if#N" labels).
func snapshotInterfaceNames() map[uint32]string {
	enum, err := callGetAdaptersAddresses()
	if err != nil {
		return map[uint32]string{}
	}
	defer enum.Release()
	names := make(map[uint32]string, 16)
	for cur := enum.head; cur != nil; cur = cur.Next {
		names[cur.IfIndex] = windows.UTF16PtrToString(cur.FriendlyName)
	}
	return names
}

// BestNonExcludedDefaultRouteLUIDv4 returns the LUID of the IPv4 default
// route owned by the best (lowest-metric) interface whose alias is NOT
// in the excluded set. Returns 0 if no such route exists (e.g. only
// excluded adapters have default routes — happens during full-tunnel
// VPN handover windows).
//
// Exported for use by the reconnect detector. Lives in this package
// because all the iphlpapi plumbing is here; the detector should not
// duplicate it.
func BestNonExcludedDefaultRouteLUIDv4(excludedAliases []string) uint64 {
	excludedLuids := make(map[uint64]struct{}, len(excludedAliases))
	for _, alias := range excludedAliases {
		if luid, ok := convertInterfaceAliasToLuid(alias); ok {
			excludedLuids[luid] = struct{}{}
		}
	}
	excluder := func(luid uint64) bool {
		_, ok := excludedLuids[luid]
		return ok
	}
	r := getDefaultRouteFiltered(afInet, excluder)
	if r == nil {
		return 0
	}
	return r.InterfaceLuid
}

// IPAdapterAddresses is a partial mirror of IP_ADAPTER_ADDRESSES_LH. We only
// touch the fields we need; the full struct is ~448 bytes on 64-bit Windows
// and we let the kernel write the full layout into our buffer.
type ipAdapterAddresses struct {
	Length        uint32
	IfIndex       uint32
	Next          *ipAdapterAddresses
	AdapterName   *byte
	FirstUnicast  uintptr
	FirstAnycast  uintptr
	FirstMulticast uintptr
	FirstDnsServer *ipAdapterDNSServerAddress
	DnsSuffix     *uint16
	Description   *uint16
	FriendlyName  *uint16
	// ... remaining ~360 bytes are not interesting for us. They live in
	// the kernel-provided buffer; we just need to skip past them when
	// walking the linked list via Next.
}

type ipAdapterDNSServerAddress struct {
	Length   uint32
	Reserved uint32
	Next     *ipAdapterDNSServerAddress
	Sockaddr sockaddrInet
	// SockaddrLength int32 — follows but we don't read it.
}

// getDNSServersForInterface returns the DNS server IPs configured on the
// named interface (FriendlyName). Returns nil on lookup failure.
//
// Uses GetAdaptersAddresses with GAA_FLAG_INCLUDE_GATEWAYS to enumerate
// every adapter; we then filter on FriendlyName. Locale-independent (no
// netsh parsing). One syscall, no subprocess.
func getDNSServersForInterface(ifaceName string) []string {
	enum, err := callGetAdaptersAddresses()
	if err != nil {
		return nil
	}
	defer enum.Release()
	for cur := enum.head; cur != nil; cur = cur.Next {
		name := windows.UTF16PtrToString(cur.FriendlyName)
		if name != ifaceName {
			continue
		}
		var servers []string
		for dns := cur.FirstDnsServer; dns != nil; dns = dns.Next {
			if ip := dns.Sockaddr.ip(); ip != nil {
				servers = append(servers, ip.String())
			}
		}
		return servers
	}
	return nil
}

// getInterfaceNameByIndex returns the FriendlyName of the adapter with the
// given Windows interface index. Returns "" on miss.
func getInterfaceNameByIndex(ifIndex uint32) string {
	enum, err := callGetAdaptersAddresses()
	if err != nil {
		return ""
	}
	defer enum.Release()
	for cur := enum.head; cur != nil; cur = cur.Next {
		if cur.IfIndex == ifIndex {
			return windows.UTF16PtrToString(cur.FriendlyName)
		}
	}
	return ""
}

// adapterEnumeration wraps a populated GetAdaptersAddresses buffer plus a
// release function. Callers MUST call Release() after they're done walking
// the linked list — that returns the underlying buffer to the pool.
//
// We hold the original backing storage (either the pooled array pointer or
// the grown slice) so the head pointer's referenced memory stays alive
// for the lifetime of the enumeration.
type adapterEnumeration struct {
	head    *ipAdapterAddresses
	pooled  *[adapterBufSize]byte // non-nil → return to pool on Release
	grown   []byte                 // non-nil → fall through to GC
	release func()
}

func (e *adapterEnumeration) Release() {
	if e == nil || e.release == nil {
		return
	}
	e.release()
	e.release = nil
}

// callGetAdaptersAddresses wraps the API with the standard "size first,
// then real call" dance. The returned linked list points into a pooled
// fixed-size buffer; callers MUST call Release() when done.
//
// If the kernel reports a buffer overflow (>16KB needed, rare — happens
// only on machines with very many adapters/VPN clients) we fall back to
// a one-shot heap allocation for that call.
func callGetAdaptersAddresses() (*adapterEnumeration, error) {
	flags := uint32(gaaFlagSkipAnycast | gaaFlagSkipMulticast | gaaFlagIncludeGateways)

	bufPtr := adapterBufPool.Get().(*[adapterBufSize]byte)
	size := uint32(adapterBufSize)

	ret, _, _ := procGetAdaptersAddresses.Call(
		uintptr(afUnspec),
		uintptr(flags),
		0,
		uintptr(unsafe.Pointer(&bufPtr[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	const errorBufferOverflow = 111
	if ret == uintptr(errorBufferOverflow) {
		// Need a bigger buffer than our pooled one. Return the pooled
		// buffer and allocate fresh. We don't put the grown buffer back
		// into the pool — the typical machine fits in 16KB; keeping a
		// growing buffer would defeat the pool's memory cap.
		adapterBufPool.Put(bufPtr)
		grown := make([]byte, size)
		ret, _, _ = procGetAdaptersAddresses.Call(
			uintptr(afUnspec),
			uintptr(flags),
			0,
			uintptr(unsafe.Pointer(&grown[0])),
			uintptr(unsafe.Pointer(&size)),
		)
		if ret != 0 {
			return nil, fmt.Errorf("GetAdaptersAddresses (grown): status %d", ret)
		}
		head := (*ipAdapterAddresses)(unsafe.Pointer(&grown[0]))
		return &adapterEnumeration{
			head:    head,
			grown:   grown,
			release: func() { /* GC'd when enum goes out of scope */ },
		}, nil
	}
	if ret != 0 {
		adapterBufPool.Put(bufPtr)
		return nil, fmt.Errorf("GetAdaptersAddresses: status %d", ret)
	}
	head := (*ipAdapterAddresses)(unsafe.Pointer(&bufPtr[0]))
	return &adapterEnumeration{
		head:   head,
		pooled: bufPtr,
		release: func() {
			adapterBufPool.Put(bufPtr)
		},
	}, nil
}

// mibIpinterfaceRow mirrors MIB_IPINTERFACE_ROW from netioapi.h (168
// bytes on amd64/arm64). GetIpInterfaceEntry takes no size parameter and
// writes the WHOLE struct into the caller's buffer, so the layout must be
// complete — the previous 120-byte buffer let the kernel write ~48 bytes
// past the end of the stack array, and read "NlMtu" from offset 56, which
// is actually DadTransmits (typically 1-3), so auto-MTU always fell back.
type mibIpinterfaceRow struct {
	Family                               uint16
	_                                    [6]byte // align InterfaceLuid to 8
	InterfaceLuid                        uint64
	InterfaceIndex                       uint32
	MaxReassemblySize                    uint32
	InterfaceIdentifier                  uint64
	MinRouterAdvertisementInterval       uint32
	MaxRouterAdvertisementInterval       uint32
	AdvertisingEnabled                   byte
	ForwardingEnabled                    byte
	WeakHostSend                         byte
	WeakHostReceive                      byte
	UseAutomaticMetric                   byte
	UseNeighborUnreachabilityDetection   byte
	ManagedAddressConfigurationSupported byte
	OtherStatefulConfigurationSupported  byte
	AdvertiseDefaultRoute                byte
	_                                    [3]byte // align RouterDiscoveryBehavior to 4
	RouterDiscoveryBehavior              int32
	DadTransmits                         uint32
	BaseReachableTime                    uint32
	RetransmitTime                       uint32
	PathMtuDiscoveryTimeout              uint32
	LinkLocalAddressBehavior             int32
	LinkLocalAddressTimeout              uint32
	ZoneIndices                          [16]uint32 // ScopeLevelCount
	SitePrefixLength                     uint32
	Metric                               uint32
	NlMtu                                uint32
	Connected                            byte
	SupportsWakeUpPatterns               byte
	SupportsNeighborDiscovery            byte
	SupportsRouterDiscovery              byte
	ReachableTime                        uint32
	TransmitOffload                      byte // NL_INTERFACE_OFFLOAD_ROD bitfield byte
	ReceiveOffload                       byte
	DisableDefaultRoutes                 byte
	_                                    [1]byte // tail pad to 8-byte struct alignment
}

// Compile-time layout assertions (both directions, so any drift fails
// the build): total size and the one field we actually read.
const _ = uintptr(168 - unsafe.Sizeof(mibIpinterfaceRow{}))
const _ = uintptr(unsafe.Sizeof(mibIpinterfaceRow{}) - 168)
const _ = uintptr(152 - unsafe.Offsetof(mibIpinterfaceRow{}.NlMtu))
const _ = uintptr(unsafe.Offsetof(mibIpinterfaceRow{}.NlMtu) - 152)

// findInterfaceMTU returns the MTU of the adapter with the given IPv4
// interface index. Uses GetIpInterfaceEntry which is locale-independent.
// Returns 0 on lookup failure.
func findInterfaceMTU(ifIndex uint32) uint32 {
	// Zero LUID + a set InterfaceIndex is the documented lookup form
	// for GetIpInterfaceEntry; the kernel fills the rest of the row.
	var row mibIpinterfaceRow
	row.Family = afInet
	row.InterfaceIndex = ifIndex

	ret, _, _ := procGetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	if ret != 0 {
		return 0
	}
	return row.NlMtu
}

// strconvU32 is a tiny helper used by tests; centralised so the formatting
// stays consistent with how we display interface indices in logs.
func strconvU32(v uint32) string {
	return strconv.FormatUint(uint64(v), 10)
}
