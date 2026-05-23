//go:build !windows

package main

import "os"

// redirectStderrToFile points os.Stderr at the given file. On non-
// Windows platforms the helper is started by macOS launchd / Linux
// systemd and they already redirect fd 2 to a known location, so
// installing the Windows-only Win32 handle hack here would be
// pointless. Keeping the signature the same so main.go is build-tag
// free.
func redirectStderrToFile(f *os.File) {
	os.Stderr = f
}
