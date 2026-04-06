//go:build darwin || linux || freebsd

package ipc

import (
	"fmt"
	"net"
)

// getPeerCredential returns the UID and PID of the process on the other end
// of a Unix domain socket. On Linux it uses SO_PEERCRED; on macOS/BSD it
// uses Getpeereid (which does not provide a PID, so pid is returned as -1).
func getPeerCredential(conn net.Conn) (uid uint32, pid int32, err error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, -1, fmt.Errorf("peercred: not a Unix connection (type %T)", conn)
	}

	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, -1, fmt.Errorf("peercred: SyscallConn: %w", err)
	}

	var peerUID uint32
	var peerPID int32
	var credErr error

	err = raw.Control(func(fd uintptr) {
		peerUID, peerPID, credErr = getPeerCredFromFD(fd)
	})
	if err != nil {
		return 0, -1, fmt.Errorf("peercred: Control: %w", err)
	}
	if credErr != nil {
		return 0, -1, credErr
	}
	return peerUID, peerPID, nil
}

// getPeerCredFromFD extracts peer credentials from a raw file descriptor.
// Platform-specific implementations follow.
func getPeerCredFromFD(fd uintptr) (uid uint32, pid int32, err error) {
	return getPeerCredPlatform(fd)
}

// verifyPeerUID checks that the peer's UID matches the expected owner.
// Returns nil if the check passes or if peer credential retrieval is not
// supported (fail-open would be worse, but on Unix we always have one of
// SO_PEERCRED or Getpeereid, so this path should not be hit).
func verifyPeerUID(conn net.Conn, expectedUID int) error {
	if expectedUID < 0 {
		// No owner restriction requested (e.g. test mode).
		return nil
	}

	peerUID, peerPID, err := getPeerCredential(conn)
	if err != nil {
		return fmt.Errorf("peer credential check failed: %w", err)
	}

	if peerUID != uint32(expectedUID) {
		return fmt.Errorf("peer UID %d does not match expected owner UID %d (pid %d)",
			peerUID, expectedUID, peerPID)
	}
	return nil
}

