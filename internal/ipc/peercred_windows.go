//go:build windows

package ipc

import (
	"errors"
	"net"
)

// getPeerCredential is a no-op on Windows. Access control is enforced by the
// SDDL on the named pipe (see transport_windows.go), so peer credential
// checking is not needed.
func getPeerCredential(conn net.Conn) (uid uint32, pid int32, err error) {
	return 0, 0, nil
}

// verifyPeerUID intentionally fails closed when an explicit UID match is
// requested. The Windows transport relies on the SDDL applied at pipe
// creation time (see transport_windows.go) to gate access; a per-
// connection UID check is not implemented here. Returning success
// unconditionally would silently grant access on any future caller that
// passes expectedUID >= 0 expecting enforcement, so we surface the gap
// instead of failing open.
//
// expectedUID < 0 means "any peer is fine" — we honour that as a no-op.
func verifyPeerUID(conn net.Conn, expectedUID int) error {
	if expectedUID < 0 {
		return nil
	}
	return errors.New("verifyPeerUID: per-connection UID check not implemented on Windows; rely on pipe SDDL")
}
