//go:build windows

package ipc

import (
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

// Listen creates a named pipe listener.
// ownerSID (parameter int is ignored on Windows; use SDDL string) controls ACL.
// For simplicity, we allow the current user and SYSTEM.
func Listen(addr string, ownerUID int) (net.Listener, error) {
	// SDDL: allow SYSTEM full access, allow current user full access.
	// D:(A;;GA;;;SY)(A;;GA;;;BA) — SYSTEM + Built-in Administrators
	// Since helper runs as admin and GUI runs as the user who triggered UAC,
	// the user has the admin token when connecting (UAC elevation token).
	// For non-admin users, they'd need an explicit SID entry.
	sddl := "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)" // SYSTEM, Admins, Interactive Users

	config := &winio.PipeConfig{
		SecurityDescriptor: sddl,
		MessageMode:        false,
		InputBufferSize:    65536,
		OutputBufferSize:   65536,
	}

	l, err := winio.ListenPipe(addr, config)
	if err != nil {
		return nil, fmt.Errorf("listen pipe %s: %w", addr, err)
	}
	return l, nil
}

// Dial connects to a named pipe.
func Dial(addr string) (net.Conn, error) {
	timeout := 5 * time.Second
	return winio.DialPipe(addr, &timeout)
}
