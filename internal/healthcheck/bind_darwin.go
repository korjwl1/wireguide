package healthcheck

import (
	"golang.org/x/sys/unix"
	"net"
)

func bindInterface(fd uintptr, iface *net.Interface, v6 bool) error {
	if v6 {
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, iface.Index)
	}
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, iface.Index)
}
