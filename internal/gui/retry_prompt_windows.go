//go:build windows

package gui

import (
	"golang.org/x/sys/windows"
)

// askHelperRetry shows a native Retry/Cancel message box when the helper
// connection fails — typically because the UAC consent prompt sat
// unanswered past ensureHelper's timeout (common at login autostart).
// The Wails app isn't running yet, so this must be a raw user32 call.
// Returns true if the user chose Retry.
//
// The previous code ran osascript here, which doesn't exist on Windows,
// so every helper timeout was silently treated as "user cancelled" and
// the GUI exited before the tray icon was ever created — while the
// still-pending UAC prompt could go on to spawn an orphaned helper.
func askHelperRetry() bool {
	const idRetry = 4 // IDRETRY — not exported by x/sys/windows
	const style = windows.MB_RETRYCANCEL | windows.MB_ICONWARNING |
		windows.MB_SETFOREGROUND | windows.MB_TOPMOST
	text, err := windows.UTF16PtrFromString(
		"WireGuide needs its helper service to manage VPN connections.\n\n" +
			"Please grant administrator access when prompted.")
	if err != nil {
		return false
	}
	caption, err := windows.UTF16PtrFromString("WireGuide")
	if err != nil {
		return false
	}
	ret, _ := windows.MessageBox(0, text, caption, style)
	return ret == idRetry
}
