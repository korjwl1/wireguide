//go:build linux

package tunnel

import (
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

func createUAPIListener(ifaceName string) (net.Listener, error) {
	file, err := ipc.UAPIOpen(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("UAPIOpen: %w", err)
	}

	listener, err := ipc.UAPIListen(ifaceName, file)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("UAPIListen: %w", err)
	}

	return listener, nil
}
