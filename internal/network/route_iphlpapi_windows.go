//go:build windows

package network

// Direct iphlpapi.dll route management — CreateIpForwardEntry2 /
// DeleteIpForwardEntry2 instead of `route.exe add/delete` and
// `netsh interface ip add/delete route`.
//
// Why move off the console tools:
//
//   1. Reliability. `route add ... metric 1` succeeds-as-far-as-the-CLI-
//      is-concerned even when the kernel rejected the row (e.g. gateway
//      is on no reachable subnet). The CLI prints "OK!" and exits 0
//      because it dispatched the IOCTL; the actual kernel error is
//      buried in a stderr line we'd have to locale-decode. iphlpapi
//      returns a numeric Win32 error code directly.
//
//   2. Latency. Every netsh / route invocation costs 100-500 ms cold
//      start (BFE service load, console allocation). A full-tunnel
//      connect fires ~6 of them serially. iphlpapi calls return in
//      microseconds.
//
//   3. Locale independence. netsh error messages are localised — Korean
//      Windows returns CP949 byte strings that we decode in windows.go
//      via decodeOEM. iphlpapi return codes are numeric.
//
//   4. Atomicity. Each iphlpapi call is a single IOCTL into nsi
//      (the kernel network store). The CLI tools shell out to the same
//      IOCTL but add their own argument parsing layer between us and it.
//
// We keep `route delete` and `netsh ... delete route` available as
// fallbacks in the disconnect/cleanup paths (see RemoveRoutes,
// Cleanup) so a partial install from a previous run that left rows
// the iphlpapi delete can't find by ID still gets swept.

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"
)

var (
	procCreateIpForwardEntry2 = modIphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2 = modIphlpapi.NewProc("DeleteIpForwardEntry2")
)

// Win32 status codes we surface specifically.
const (
	winErrorObjectAlreadyExists uint32 = 5010 // ERROR_OBJECT_ALREADY_EXISTS
	winErrorNotFound            uint32 = 1168 // ERROR_NOT_FOUND
)

// fillSockaddrInet writes a SOCKADDR_IN or SOCKADDR_IN6 into the given
// sockaddrInet buffer. Used for IP_ADDRESS_PREFIX.Prefix and
// MIB_IPFORWARD_ROW2.NextHop.
//
// For SOCKADDR_IN we write: family(2 LE) + port(2)=0 + addr(4 BE) +
// zero(8). For SOCKADDR_IN6: family(2 LE) + port(2)=0 + flowinfo(4)=0 +
// addr(16 BE) + scope(4)=0. The kernel only cares about family and
// the address bytes; other fields default to zero.
func fillSockaddrInet(sa *sockaddrInet, ip net.IP) {
	for i := range sa.raw {
		sa.raw[i] = 0
	}
	if v4 := ip.To4(); v4 != nil {
		*(*uint16)(unsafe.Pointer(&sa.raw[0])) = afInet
		copy(sa.raw[4:8], v4)
		return
	}
	if v6 := ip.To16(); v6 != nil {
		*(*uint16)(unsafe.Pointer(&sa.raw[0])) = afInet6
		copy(sa.raw[8:24], v6)
	}
}

// fillSockaddrInetUnspec writes the family with an all-zero address —
// the canonical "on-link" / "no gateway" form used for NextHop on
// routes that go straight out an interface (wintun /1 split routes,
// for example).
func fillSockaddrInetUnspec(sa *sockaddrInet, family uint16) {
	for i := range sa.raw {
		sa.raw[i] = 0
	}
	*(*uint16)(unsafe.Pointer(&sa.raw[0])) = family
}

// AddIpForwardRoute installs one route via iphlpapi. Either ifaceLuid
// or ifaceIndex must be non-zero (LUID wins when both are set, per the
// CreateIpForwardEntry2 contract). `nextHop` may be nil for on-link
// routes — the function fills in an unspecified address of the same
// family as `dest`.
//
// `prefixLen` is the destination prefix length (0-32 for IPv4, 0-128
// for IPv6). `metric` is the route metric (0 is fine; effective metric
// will be route metric + interface metric).
//
// Returns nil on success. ERROR_OBJECT_ALREADY_EXISTS is surfaced as a
// distinguishable error so callers can decide whether duplicates are
// fatal (typical answer: no).
func AddIpForwardRoute(ifaceLuid uint64, ifaceIndex uint32, dest net.IP, prefixLen uint8, nextHop net.IP, metric uint32) error {
	if dest == nil {
		return fmt.Errorf("AddIpForwardRoute: nil destination")
	}
	if ifaceLuid == 0 && ifaceIndex == 0 {
		return fmt.Errorf("AddIpForwardRoute: must specify ifaceLuid or ifaceIndex")
	}
	row := mibIpforwardRow2{
		InterfaceLuid:  ifaceLuid,
		InterfaceIndex: ifaceIndex,
		Metric:         metric,
	}
	// DestinationPrefix
	fillSockaddrInet(&row.DestinationPrefix.Prefix, dest)
	row.DestinationPrefix.PrefixLength = prefixLen
	// NextHop
	var family uint16 = afInet
	if dest.To4() == nil {
		family = afInet6
	}
	if nextHop == nil || nextHop.IsUnspecified() {
		fillSockaddrInetUnspec(&row.NextHop, family)
	} else {
		fillSockaddrInet(&row.NextHop, nextHop)
	}
	ret, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
	if ret != 0 {
		status := uint32(ret)
		if status == winErrorObjectAlreadyExists {
			return errRouteAlreadyExists
		}
		return fmt.Errorf("CreateIpForwardEntry2(%s/%d via %v): status %d", dest, prefixLen, nextHop, status)
	}
	return nil
}

// DeleteIpForwardRoute removes one route via iphlpapi. The arguments
// are matched against the kernel route table to identify the row to
// delete. Returns nil on success. ERROR_NOT_FOUND is surfaced as a
// distinguishable error so callers can ignore it during best-effort
// cleanup.
func DeleteIpForwardRoute(ifaceLuid uint64, ifaceIndex uint32, dest net.IP, prefixLen uint8, nextHop net.IP) error {
	if dest == nil {
		return fmt.Errorf("DeleteIpForwardRoute: nil destination")
	}
	row := mibIpforwardRow2{
		InterfaceLuid:  ifaceLuid,
		InterfaceIndex: ifaceIndex,
	}
	fillSockaddrInet(&row.DestinationPrefix.Prefix, dest)
	row.DestinationPrefix.PrefixLength = prefixLen
	var family uint16 = afInet
	if dest.To4() == nil {
		family = afInet6
	}
	if nextHop == nil || nextHop.IsUnspecified() {
		fillSockaddrInetUnspec(&row.NextHop, family)
	} else {
		fillSockaddrInet(&row.NextHop, nextHop)
	}
	ret, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
	if ret != 0 {
		status := uint32(ret)
		if status == winErrorNotFound {
			return errRouteNotFound
		}
		return fmt.Errorf("DeleteIpForwardEntry2(%s/%d via %v): status %d", dest, prefixLen, nextHop, status)
	}
	return nil
}

// errRouteAlreadyExists / errRouteNotFound are sentinels for the
// distinguishable status codes. Callers should use errors.Is to check.
var (
	errRouteAlreadyExists = fmt.Errorf("route already exists")
	errRouteNotFound      = fmt.Errorf("route not found")
)

// IsRouteAlreadyExists reports whether err is ERROR_OBJECT_ALREADY_EXISTS
// from AddIpForwardRoute.
func IsRouteAlreadyExists(err error) bool { return err == errRouteAlreadyExists }

// IsRouteNotFound reports whether err is ERROR_NOT_FOUND from
// DeleteIpForwardRoute.
func IsRouteNotFound(err error) bool { return err == errRouteNotFound }

// VerifyIpForwardRoute reports whether a route matching the given
// (dest, prefix, ifaceLuid) tuple is currently in the kernel route
// table. Used by addFullTunnelRoutes as a post-install sanity check
// when the install API returned success — defends against the rare
// kernel-accepted-but-invalid race where the row exists in nsi but
// the dataplane doesn't honor it yet (typical after a wintun adapter
// has just been created and the BFE hasn't picked up the LUID).
//
// `verifyTimeout` and polling are the caller's responsibility; this
// is a single point-in-time check.
func VerifyIpForwardRoute(ifaceLuid uint64, dest net.IP, prefixLen uint8) bool {
	if dest == nil {
		return false
	}
	family := uint32(afInet)
	if dest.To4() == nil {
		family = afInet6
	}
	var tablePtr unsafe.Pointer
	ret, _, _ := procGetIpForwardTable2.Call(uintptr(family), uintptr(unsafe.Pointer(&tablePtr)))
	if ret != 0 || tablePtr == nil {
		return false
	}
	defer freeMibTable(tablePtr)

	hdr := (*mibIpforwardTable2)(tablePtr)
	n := int(hdr.NumEntries)
	if n == 0 {
		return false
	}
	rowsBase := unsafe.Pointer(uintptr(tablePtr) + unsafe.Sizeof(mibIpforwardTable2{}))
	rowSize := unsafe.Sizeof(mibIpforwardRow2{})

	want := canonicalIP(dest)
	for i := 0; i < n; i++ {
		row := (*mibIpforwardRow2)(unsafe.Pointer(uintptr(rowsBase) + uintptr(i)*rowSize))
		if row.InterfaceLuid != ifaceLuid {
			continue
		}
		if row.DestinationPrefix.PrefixLength != prefixLen {
			continue
		}
		got := row.DestinationPrefix.Prefix.ip()
		if got == nil {
			continue
		}
		if canonicalIP(got).Equal(want) {
			return true
		}
	}
	return false
}

// canonicalIP coerces a net.IP to its 4-byte form when it's IPv4-in-
// IPv6 — ensures Equal() comparisons across read-back-from-kernel
// (which may be 4-byte form) and user-supplied (which may be 16-byte
// form) representations succeed.
func canonicalIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// LuidFromInterfaceAlias is the exported wrapper around the existing
// convertInterfaceAliasToLuid for callers outside this package (the
// firewall's endpoint protection needs the tunnel LUID; the route
// helpers need the physical LUID via getDefaultRoute).
func LuidFromInterfaceAlias(alias string) (uint64, bool) {
	return convertInterfaceAliasToLuid(alias)
}

// DefaultRouteV4LuidAndIndex returns the (LUID, ifIndex) of the
// physical adapter holding the IPv4 default route, plus its nexthop
// IP. Returns (0, 0, nil) if no default route is installed (e.g. boot-
// before-DHCP) or all default routes are owned by excluded interfaces.
//
// `excludedAliases` lets callers skip e.g. an existing tunnel adapter
// when computing "what was the physical underlay before we connected".
func DefaultRouteV4LuidAndIndex(excludedAliases []string) (uint64, uint32, net.IP) {
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
		return 0, 0, nil
	}
	return r.InterfaceLuid, r.InterfaceIndex, r.NextHop
}

// DefaultRouteV6LuidAndIndex mirrors DefaultRouteV4LuidAndIndex for IPv6.
func DefaultRouteV6LuidAndIndex(excludedAliases []string) (uint64, uint32, net.IP) {
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
	r := getDefaultRouteFiltered(afInet6, excluder)
	if r == nil {
		return 0, 0, nil
	}
	return r.InterfaceLuid, r.InterfaceIndex, r.NextHop
}

// Defensive: encoding/binary is imported by both this file's siblings;
// keep an explicit reference so a future reorg doesn't strip it.
var _ = binary.BigEndian
