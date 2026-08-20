//go:build windows

package gui

import (
	"strings"

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
// detail is the underlying error, appended so a persistent failure is
// diagnosable from the dialog instead of retrying blind.
func askHelperRetry(detail string) bool {
	const idRetry = 4 // IDRETRY — not exported by x/sys/windows
	const style = windows.MB_RETRYCANCEL | windows.MB_ICONWARNING |
		windows.MB_SETFOREGROUND | windows.MB_TOPMOST
	msg := "WireGuide needs its helper service to manage VPN connections.\n\n" +
		"Please grant administrator access when prompted."
	if d := strings.TrimSpace(detail); d != "" {
		if r := []rune(d); len(r) > 400 {
			d = "…" + string(r[len(r)-400:])
		}
		msg += "\n\nDetails: " + d
	}
	text, err := windows.UTF16PtrFromString(msg)
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
