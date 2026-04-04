package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const launchDaemonLabel = "com.wireguide.daemon"

// InstallAutostart sets up OS-level autostart for the GUI app.
func InstallAutostart(appPath string) error {
	switch runtime.GOOS {
	case "darwin":
		return installMacAutostart(appPath)
	case "linux":
		return installLinuxAutostart(appPath)
	case "windows":
		return installWindowsAutostart(appPath)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// RemoveAutostart removes OS-level autostart.
func RemoveAutostart() error {
	switch runtime.GOOS {
	case "darwin":
		return removeMacAutostart()
	case "linux":
		return removeLinuxAutostart()
	case "windows":
		return removeWindowsAutostart()
	default:
		return nil
	}
}

// --- macOS: LaunchAgent ---

func installMacAutostart(appPath string) error {
	home, _ := os.UserHomeDir()
	plistDir := filepath.Join(home, "Library", "LaunchAgents")
	os.MkdirAll(plistDir, 0755)

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.wireguide.gui</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>
`, appPath)

	return os.WriteFile(filepath.Join(plistDir, "com.wireguide.gui.plist"), []byte(plist), 0644)
}

func removeMacAutostart() error {
	home, _ := os.UserHomeDir()
	return os.Remove(filepath.Join(home, "Library", "LaunchAgents", "com.wireguide.gui.plist"))
}

// --- Linux: XDG autostart ---

func installLinuxAutostart(appPath string) error {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, _ := os.UserHomeDir()
		configHome = filepath.Join(home, ".config")
	}
	autostartDir := filepath.Join(configHome, "autostart")
	os.MkdirAll(autostartDir, 0755)

	desktop := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=WireGuide
Exec=%s
Icon=wireguide
Terminal=false
StartupNotify=false
X-GNOME-Autostart-enabled=true
`, appPath)

	return os.WriteFile(filepath.Join(autostartDir, "wireguide.desktop"), []byte(desktop), 0644)
}

func removeLinuxAutostart() error {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, _ := os.UserHomeDir()
		configHome = filepath.Join(home, ".config")
	}
	return os.Remove(filepath.Join(configHome, "autostart", "wireguide.desktop"))
}

// --- Windows: Registry Run key ---

func installWindowsAutostart(appPath string) error {
	return exec.Command("reg", "add",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", "WireGuide", "/t", "REG_SZ", "/d", appPath, "/f").Run()
}

func removeWindowsAutostart() error {
	cmd := exec.Command("reg", "delete",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", "WireGuide", "/f")
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "not found") {
		return err
	}
	return nil
}
