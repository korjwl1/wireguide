//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// redirectStderrToFile points os.Stderr AND the Win32 STD_ERROR_HANDLE
// at the given file. Without the Win32 step, Go's runtime fatal-error
// writer (gwrite) keeps using the original handle that powershell
// `Start-Process -Verb RunAs -WindowStyle Hidden` gave us — which is
// detached — so any `fatal error: concurrent map writes` style throw
// vanishes. After both redirections land, both slog text output and
// runtime throws end up in our file. Best-effort: a failure of the
// Win32 call is logged-and-ignored so the helper still starts.
func redirectStderrToFile(f *os.File) {
	os.Stderr = f
	_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd()))
}
