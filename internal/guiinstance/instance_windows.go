//go:build windows

package guiinstance

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

var allowSetForegroundWindow = windows.NewLazySystemDLL("user32.dll").NewProc("AllowSetForegroundWindow")

func identity() (sid string, session uint32, err error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", 0, err
	}
	if err = windows.ProcessIdToSessionId(uint32(os.Getpid()), &session); err != nil {
		return "", 0, err
	}
	return user.User.Sid.String(), session, nil
}

// Acquire returns the primary's reservation, or nil after asking an existing
// GUI to show its window. go-winio's initial FILE_CREATE is exclusive, so the
// activation pipe itself is the reservation; no stale PID file or leaked mutex
// handle can prevent restart. The helper uses a separate pipe and is unaffected.
func Acquire() (*Instance, error) {
	sid, session, err := identity()
	if err != nil {
		return nil, fmt.Errorf("GUI instance identity: %w", err)
	}
	path := fmt.Sprintf(`\\.\pipe\wireguide.gui.%s.%d`, sid, session)
	ctx, cancel := context.WithTimeout(context.Background(), contactTimeout)
	defer cancel()
	return acquireAt(ctx, path, sid, session)
}

func acquireAt(ctx context.Context, path, sid string, session uint32) (*Instance, error) {
	return acquire(ctx, func() (net.Listener, error) {
		return winio.ListenPipe(path, &winio.PipeConfig{
			SecurityDescriptor: fmt.Sprintf("D:P(A;;GA;;;%s)(A;;GA;;;SY)", sid),
			InputBufferSize:    64, OutputBufferSize: 64,
		})
	}, func(ctx context.Context) (net.Conn, error) { return winio.DialPipeContext(ctx, path) }, func(c net.Conn) error { return grantForeground(c, sid, session) })
}

func grantForeground(c net.Conn, sid string, session uint32) error {
	handle, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("GUI activation pipe has no handle")
	}
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(windows.Handle(handle.Fd()), &pid); err != nil {
		return err
	}
	var serverSession uint32
	if err := windows.ProcessIdToSessionId(pid, &serverSession); err != nil {
		return err
	}
	if serverSession != session {
		return fmt.Errorf("GUI activation belongs to another session")
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err = windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	if user.User.Sid.String() != sid {
		return fmt.Errorf("GUI activation belongs to another user")
	}
	// Pass only this launch's foreground permission to the existing process.
	// Windows may still refuse focus (e.g. a locked desktop); showing the window
	// remains useful and must not cause another GUI to start.
	_, _, _ = allowSetForegroundWindow.Call(uintptr(pid))
	return nil
}
