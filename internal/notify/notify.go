package notify

import (
	"log/slog"
	"os/exec"
	"runtime"
	"strings"

	"github.com/korjwl1/wireguide/internal/sysexec"
)

// SendNotification sends an OS-level notification. Best-effort: failures are
// logged at debug level but never propagated.
func SendNotification(title, message string) {
	// Strip control characters that would otherwise break the
	// notification subsystem's display:
	//   - NUL terminates C strings; osascript/notify-send silently
	//     truncate at the first NUL.
	//   - \n / \r split notify-send into multiple notifications on
	//     some implementations.
	//   - Bell/escape sequences can mis-render in toast renderers.
	title = sanitizeNotificationText(title)
	message = sanitizeNotificationText(message)

	// If sanitization left both empty (input was pure control chars
	// or whitespace), skip the notification entirely. osascript on
	// macOS happily displays a blank notification card that the user
	// can't dismiss; notify-send and PowerShell handle it but the
	// result is just visual noise.
	if title == "" && message == "" {
		return
	}

	var err error
	switch runtime.GOOS {
	case "darwin":
		err = notifyMac(title, message)
	case "linux":
		err = notifyLinux(title, message)
	case "windows":
		err = notifyWindows(title, message)
	}
	if err != nil {
		slog.Debug("notification failed", "error", err)
	}
}

// sanitizeNotificationText replaces control characters (NUL, BEL, ESC,
// CR, LF, TAB and other C0/C1 chars) with single spaces, collapsing
// runs of whitespace. The exec.Command interface itself is shell-safe
// (no shell invocation), so this is purely a display-correctness fix.
func sanitizeNotificationText(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		// Treat C0 (U+0000..U+001F) and DEL (U+007F) as whitespace.
		// Allow tab/space through as a single space.
		if r < 0x20 || r == 0x7F {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = false
	}
	return strings.TrimSpace(b.String())
}

func notifyMac(title, message string) error {
	script := `on run argv
set theMessage to item 1 of argv
set theTitle to item 2 of argv
display notification theMessage with title theTitle
end run`
	return exec.Command("osascript", "-e", script, message, title).Run()
}

func notifyLinux(title, message string) error {
	return exec.Command("notify-send", title, message, "-a", "WireGuide").Run()
}

func notifyWindows(title, message string) error {
	// PowerShell toast notification — use single-quoted strings with doubled
	// single quotes to prevent PowerShell injection.
	// Sanitize newlines to prevent multi-line injection into the PS script.
	safeTitle := strings.ReplaceAll(title, "'", "''")
	safeTitle = strings.ReplaceAll(safeTitle, "\n", " ")
	safeTitle = strings.ReplaceAll(safeTitle, "\r", " ")
	safeMsg := strings.ReplaceAll(message, "'", "''")
	safeMsg = strings.ReplaceAll(safeMsg, "\n", " ")
	safeMsg = strings.ReplaceAll(safeMsg, "\r", " ")
	ps := `[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$textNodes = $template.GetElementsByTagName("text")
$textNodes.Item(0).AppendChild($template.CreateTextNode('` + safeTitle + `')) | Out-Null
$textNodes.Item(1).AppendChild($template.CreateTextNode('` + safeMsg + `')) | Out-Null
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("WireGuide").Show($toast)`
	cmd := exec.Command("powershell", "-Command", ps)
	sysexec.Hide(cmd)
	return cmd.Run()
}
