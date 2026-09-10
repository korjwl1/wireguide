package healthcheck

import (
	"golang.org/x/sys/unix"
	"net"
)

func bindInterface(fd uintptr, iface *net.Interface, v6 bool) error {
	return unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface.Name)
}
