package notify

import (
	"log/slog"
	"os/exec"
	"runtime"
	"strings"
)

// SendNotification sends an OS-level notification. Best-effort: failures are
// logged at debug level but never propagated.
func SendNotification(title, message string) {
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
	return exec.Command("powershell", "-Command", ps).Run()
}
