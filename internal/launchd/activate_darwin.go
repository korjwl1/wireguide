//go:build darwin && cgo

package launchd

/*
#include <launch.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"net"
	"os"
	"unsafe"
)

// Listeners returns the listeners launchd bound for this job's "Listeners"
// socket entry. The returned listeners never unlink the socket path on close:
// the socket belongs to launchd, which keeps it (and re-launches the job on
// the next connect) after this process exits.
//
// Returns ErrNotManaged when the process was not started by launchd and
// ErrNoSocketEntry when the plist declares no such socket.
func Listeners() ([]net.Listener, error) {
	name := C.CString(SocketName)
	defer C.free(unsafe.Pointer(name))

	var fds *C.int
	var cnt C.size_t
	if rc := C.launch_activate_socket(name, &fds, &cnt); rc != 0 {
		return nil, mapActivateError(int(rc))
	}
	if fds == nil {
		return nil, ErrNoSocketEntry
	}
	defer C.free(unsafe.Pointer(fds))

	raw := unsafe.Slice(fds, int(cnt))
	listeners := make([]net.Listener, 0, len(raw))
	for i, fd := range raw {
		f := os.NewFile(uintptr(fd), fmt.Sprintf("launchd-%s-%d", SocketName, i))
		l, err := net.FileListener(f)
		// FileListener dups the descriptor; release the original either way.
		f.Close()
		if err != nil {
			for _, prev := range listeners {
				prev.Close()
			}
			// Remaining fds are leaked deliberately-short-lived: the helper
			// exits non-zero on this error.
			return nil, fmt.Errorf("launchd: adopt listener %d: %w", i, err)
		}
		if ul, ok := l.(*net.UnixListener); ok {
			ul.SetUnlinkOnClose(false)
		}
		listeners = append(listeners, l)
	}
	return listeners, nil
}
