//go:build darwin || freebsd

package ipc

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// getPeerCredPlatform uses LOCAL_PEERCRED on macOS/BSD to retrieve the peer's UID
// via the Xucred structure. PID is not available through this mechanism, so it
// is returned as -1.
func getPeerCredPlatform(fd uintptr) (uid uint32, pid int32, err error) {
	cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, -1, fmt.Errorf("LOCAL_PEERCRED: %w", err)
	}
	return cred.Uid, -1, nil
}
