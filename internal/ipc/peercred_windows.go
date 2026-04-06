//go:build windows

package ipc

import "net"

// getPeerCredential is a no-op on Windows. Access control is enforced by the
// SDDL on the named pipe (see transport_windows.go), so peer credential
// checking is not needed.
func getPeerCredential(conn net.Conn) (uid uint32, pid int32, err error) {
	return 0, 0, nil
}

// verifyPeerUID is a no-op on Windows. Pipe SDDL handles authorization.
func verifyPeerUID(conn net.Conn, expectedUID int) error {
	return nil
}
