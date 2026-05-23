//go:build windows

package tunnel

import (
	"log/slog"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// cleanupStaleWintunAdapter removes a leftover "WireGuide" wintun adapter
// from a previous run before we attempt CreateTUN. Without this, a helper
// crash that didn't tear down the adapter leaves it pinned to the dead
// instance and the next CreateTUN may fail with ERROR_ALREADY_EXISTS
// (1073, also reported as "object already exists").
//
// Best-effort. If wintun.dll isn't loadable (e.g. wintun-go embedded a
// different path) we simply do nothing and let the regular CreateTUN
// path either succeed or fail with its own error message.
func cleanupStaleWintunAdapter(name string) {
	dll, err := windows.LoadDLL("wintun.dll")
	if err != nil {
		// wintun-go may extract the DLL to a temp location only after
		// the first CreateAdapter call. In that case we can't
		// pre-clean, but the subsequent CreateAdapter itself returns
		// the existing adapter, which is OK.
		slog.Debug("wintun.dll not loadable for pre-cleanup", "error", err)
		return
	}
	defer dll.Release()

	openProc, err := dll.FindProc("WintunOpenAdapter")
	if err != nil {
		return
	}
	closeProc, err := dll.FindProc("WintunCloseAdapter")
	if err != nil {
		return
	}

	// Names cross the FFI boundary as null-terminated UTF-16.
	utf16Name, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	handle, _, _ := openProc.Call(uintptr(unsafe.Pointer(utf16Name)))
	if handle == 0 {
		// No leftover adapter — common case, no-op.
		return
	}
	slog.Warn("found stale wintun adapter from previous run, closing", "name", name)
	closeProc.Call(handle)
}
