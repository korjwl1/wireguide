package healthcheck

import (
	"fmt"
	"math/bits"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

func bindInterface(fd uintptr, iface *net.Interface, v6 bool) error {
	// IP_UNICAST_IF (31) takes the IPv4 index in network byte order;
	// IPV6_UNICAST_IF (31) takes its index in host byte order.
	if v6 {
		index, err := ipv6InterfaceIndex(iface.Index)
		if err != nil {
			return err
		}
		return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, 31, index)
	}
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(bits.ReverseBytes32(uint32(iface.Index))))
}

// Windows can assign different indices to the two address families. Go's
// net.Interface.Index prefers IfIndex, so resolve Ipv6IfIndex explicitly.
func ipv6InterfaceIndex(index int) (int, error) {
	size := uint32(15000)
	for attempts := 0; attempts < 3; attempts++ {
		buffer := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return 0, err
		}
		for adapter := first; adapter != nil; adapter = adapter.Next {
			candidate := adapter.IfIndex
			if candidate == 0 {
				candidate = adapter.Ipv6IfIndex
			}
			if int(candidate) == index && adapter.Ipv6IfIndex != 0 {
				return int(adapter.Ipv6IfIndex), nil
			}
		}
		break
	}
	return 0, fmt.Errorf("no IPv6 interface index for interface %d", index)
}
