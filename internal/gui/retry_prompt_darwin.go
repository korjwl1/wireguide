//go:build darwin

package gui

import (
	"fmt"
	"os/exec"
	"strings"
)

// askHelperRetry shows a native Retry/Quit dialog when the helper
// connection fails. Uses osascript because the Wails app isn't running
// yet at this point in startup. Returns true if the user chose Retry.
//
// detail is the underlying error (launchctl / osascript output included
// since issue #41) — shown so a persistent failure is diagnosable from
// the dialog instead of looping blind.
func askHelperRetry(detail string) bool {
	msg := `WireGuide needs its helper service to manage VPN connections.\n\nPlease grant administrator access when prompted.`
	if d := appleScriptSanitize(detail, 400); d != "" {
		msg += `\n\nDetails: ` + d
	}
	retryCmd := fmt.Sprintf(`display dialog "%s" buttons {"Quit", "Retry"} default button "Retry" with title "WireGuide" with icon caution`, msg)
	out, err := exec.Command("osascript", "-e", retryCmd).Output()
	if err != nil || strings.Contains(string(out), "Quit") {
		return false
	}
	return true
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
