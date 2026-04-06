//go:build linux

package ipc

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// getPeerCredPlatform uses SO_PEERCRED on Linux to retrieve the peer's UID and PID.
func getPeerCredPlatform(fd uintptr) (uid uint32, pid int32, err error) {
	cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, -1, fmt.Errorf("SO_PEERCRED: %w", err)
	}
	return cred.Uid, cred.Pid, nil
}
