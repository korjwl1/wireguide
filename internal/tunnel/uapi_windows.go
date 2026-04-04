//go:build windows

package tunnel

import (
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

func createUAPIListener(ifaceName string) (net.Listener, error) {
	// On Windows, UAPIListen only takes the name
	return ipc.UAPIListen(ifaceName)
}
