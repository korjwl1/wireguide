//go:build darwin

package gui

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/korjwl1/wireguide/internal/elevate"
)

// askHelperRetry shows a native Retry/Quit dialog when the helper
// connection fails. Uses osascript because the Wails app isn't running
// yet at this point in startup. Returns true if the user chose Retry.
//
// cause is the underlying error (launchctl / osascript output included
// since issue #41) — shown so a persistent failure is diagnosable from
// the dialog instead of looping blind.
func askHelperRetry(cause error) bool {
	msg := `WireGuide needs its helper service to manage VPN connections.\n\nPlease grant administrator access when prompted.`
	buttons := `{"Quit", "Retry"}`
	if errors.Is(cause, elevate.ErrBackgroundDisabled) {
		msg = `WireGuide's helper service is disabled.\n\nAllow WireGuide in System Settings > General > Login Items & Extensions, then choose Retry.`
		buttons = `{"Quit", "Open Settings", "Retry"}`
	}
	if d := appleScriptSanitize(cause.Error(), 600); d != "" {
		msg += `\n\nDetails: ` + d
	}
	for {
		retryCmd := fmt.Sprintf(`button returned of (display dialog "%s" buttons %s default button "Retry" with title "WireGuide" with icon caution)`, msg, buttons)
		out, err := exec.Command("osascript", "-e", retryCmd).Output()
		if err != nil {
			return false
		}
		switch strings.TrimSpace(string(out)) {
		case "Retry":
			return true
		case "Open Settings":
			// Opening Settings does not retry installation or change the user's choice.
			_ = exec.Command("open", "x-apple.systempreferences:com.apple.LoginItems-Settings.extension").Run()
		default:
			return false
		}
	}
}

// appleScriptSanitize makes an arbitrary error string safe to embed in a
// double-quoted AppleScript literal that is itself passed as a single
// `osascript -e` argument: escape backslashes and quotes, fold real
// newlines into AppleScript "\n" escapes, and truncate to max runes
// (keeping the tail, where launchctl errors land).
func appleScriptSanitize(s string, max int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > max {
		s = "…" + string(r[len(r)-max:])
	}
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\r\n", `\n`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\n`)
	return s
}
