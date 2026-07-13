//go:build windows

package wifi

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modIphlpapi      = syscall.NewLazyDLL("iphlpapi.dll")
	procGetBestRoute = modIphlpapi.NewProc("GetBestRoute")
	procSendARP      = modIphlpapi.NewProc("SendARP")
)

// mibIPForwardRow mirrors MIB_IPFORWARDROW (ipmib.h): 14 consecutive
// DWORDs. Only dwForwardNextHop is read; the rest exist so the kernel
// has the full buffer to write into.
type mibIPForwardRow struct {
	dest      uint32
	mask      uint32
	policy    uint32
	nextHop   uint32
	ifIndex   uint32
	fType     uint32
	proto     uint32
	age       uint32
	nextHopAS uint32
	metric1   uint32
	metric2   uint32
	metric3   uint32
	metric4   uint32
	metric5   uint32
}

// GatewayMAC returns the lower-cased MAC of the IPv4 default gateway.
// GetBestRoute to a public address yields the gateway (dwForwardNextHop);
// SendARP resolves that gateway IP to its MAC from the neighbour cache.
// Both are unprivileged and locale-independent. "" on any failure.
func GatewayMAC() string {
	// 8.8.8.8 as an IN_ADDR DWORD (network byte order == 0x08080808).
	const dest = uint32(8) | uint32(8)<<8 | uint32(8)<<16 | uint32(8)<<24
	var row mibIPForwardRow
	ret, _, _ := procGetBestRoute.Call(uintptr(dest), 0, uintptr(unsafe.Pointer(&row)))
	if ret != 0 || row.nextHop == 0 {
		return ""
	}
	var mac [8]byte
	macLen := uint32(6)
	ret2, _, _ := procSendARP.Call(
		uintptr(row.nextHop), 0,
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	if ret2 != 0 || macLen < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
