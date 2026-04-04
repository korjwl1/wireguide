package notify

import (
	"fmt"
	"os/exec"
	"runtime"
)

// SendNotification sends an OS-level notification.
func SendNotification(title, message string) {
	switch runtime.GOOS {
	case "darwin":
		notifyMac(title, message)
	case "linux":
		notifyLinux(title, message)
	case "windows":
		notifyWindows(title, message)
	}
}

func notifyMac(title, message string) {
	script := fmt.Sprintf(`display notification "%s" with title "%s"`, message, title)
	exec.Command("osascript", "-e", script).Run()
}

func notifyLinux(title, message string) {
	// Try notify-send (libnotify)
	exec.Command("notify-send", title, message, "-a", "WireGuide").Run()
}

func notifyWindows(title, message string) {
	// PowerShell toast notification
	ps := fmt.Sprintf(`
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$textNodes = $template.GetElementsByTagName("text")
$textNodes.Item(0).AppendChild($template.CreateTextNode("%s")) | Out-Null
$textNodes.Item(1).AppendChild($template.CreateTextNode("%s")) | Out-Null
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("WireGuide").Show($toast)
`, title, message)
	exec.Command("powershell", "-Command", ps).Run()
}
