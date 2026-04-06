//go:build windows

package ipc

import (
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// Listen creates a named pipe listener.
// ownerSID (parameter int is ignored on Windows; use SDDL string) controls ACL.
func Listen(addr string, ownerUID int) (net.Listener, error) {
	// H13: SYSTEM and Administrators get full control (GA). Interactive Users
	// (IU / S-1-5-4) get read+write only (GRGW) so the unprivileged GUI
	// process can connect to the helper pipe without requiring elevation.
	// IU covers any user who has logged on interactively — this is the
	// minimal group that enables the privilege-separation design.
	sddl := "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

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

// Dial connects to a named pipe and verifies the server is owned by a trusted
// principal (Local System or Built-in Administrators).
func Dial(addr string) (net.Conn, error) {
	timeout := 5 * time.Second
	conn, err := winio.DialPipe(addr, &timeout)
	if err != nil {
		return nil, err
	}

	// H15: Verify pipe ownership after connecting. Extract the underlying
	// file handle and check the owner SID.
	if err := verifyPipeOwner(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("pipe ownership verification failed: %w", err)
	}

	return conn, nil
}

// verifyPipeOwner checks that the named pipe is owned by Local System (SY)
// or Built-in Administrators (BA). This prevents a malicious process from
// creating a pipe with the same name before the legitimate helper starts.
func verifyPipeOwner(conn net.Conn) error {
	// The go-winio pipe connection embeds a *os.File. We need the Windows
	// handle to call GetSecurityInfo. Use a type assertion to get the
	// syscall handle.
	type handleGetter interface {
		Fd() uintptr
	}
	hg, ok := conn.(handleGetter)
	if !ok {
		// Fail closed: if we can't get the handle, reject the connection.
		// This could happen if go-winio changes its internal types.
		return fmt.Errorf("cannot extract file handle for pipe ownership verification")
	}
	handle := windows.Handle(hg.Fd())

	// Get the owner SID of the pipe.
	sd, err := windows.GetSecurityInfo(handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("GetSecurityInfo: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("getting owner SID: %w", err)
	}
	if owner == nil {
		return fmt.Errorf("pipe has no owner SID")
	}

	// Check against well-known SIDs: Local System and Built-in Administrators.
	localSystem, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	builtinAdmins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)

	if (localSystem != nil && windows.EqualSid(owner, localSystem)) ||
		(builtinAdmins != nil && windows.EqualSid(owner, builtinAdmins)) {
		return nil
	}

	return fmt.Errorf("pipe owned by unexpected SID: %s", sidToString(owner))
}

func sidToString(sid *windows.SID) string {
	if sid == nil {
		return "<nil>"
	}
	// Use ConvertSidToStringSid via unsafe pointer to get the string form.
	var strSid *uint16
	err := windows.ConvertSidToStringSid(sid, &strSid)
	if err != nil {
		return "<unknown>"
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(strSid)))
	return windows.UTF16PtrToString(strSid)
}
