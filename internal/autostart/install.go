package autostart

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/korjwl1/wireguide/internal/sysexec"
)

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
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	plistDir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(plistDir, 0755); err != nil {
		return fmt.Errorf("creating LaunchAgents dir: %w", err)
	}

	// XML-escape appPath to prevent plist injection from special characters.
	// xml.EscapeText returning an error means the escaping itself failed
	// (extremely rare — only from the io.Writer surface) and the buffer
	// may contain partial unescaped bytes. We MUST refuse to write the
	// plist in that case, otherwise an attacker who controls the path
	// could inject `</string>...<key>...` and modify our plist.
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(appPath)); err != nil {
		return fmt.Errorf("xml-escape app path: %w", err)
	}
	safeAppPath := b.String()

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
</dict>
</plist>
`, safeAppPath)

	return os.WriteFile(filepath.Join(plistDir, "com.wireguide.gui.plist"), []byte(plist), 0644)
}

func removeMacAutostart() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	return os.Remove(filepath.Join(home, "Library", "LaunchAgents", "com.wireguide.gui.plist"))
}

// --- Linux: XDG autostart ---

func installLinuxAutostart(appPath string) error {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine home directory: %w", err)
		}
		configHome = filepath.Join(home, ".config")
	}
	autostartDir := filepath.Join(configHome, "autostart")
	if err := os.MkdirAll(autostartDir, 0755); err != nil {
		return fmt.Errorf("creating autostart dir: %w", err)
	}

	// Quote the Exec path per Desktop Entry Spec to handle spaces/special chars.
	quotedPath := `"` + strings.ReplaceAll(appPath, `"`, `\"`) + `"`
	desktop := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=WireGuide
Exec=%s
Icon=wireguide
Terminal=false
StartupNotify=false
X-GNOME-Autostart-enabled=true
`, quotedPath)

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
	// M15: Wrap the path in quotes so spaces in the path are handled correctly
	// by the Windows shell when the registry value is used to launch the app.
	quotedPath := `"` + appPath + `"`
	cmd := exec.Command("reg", "add",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", "WireGuide", "/t", "REG_SZ", "/d", quotedPath, "/f")
	sysexec.Hide(cmd)
	return cmd.Run()
}

func removeWindowsAutostart() error {
	cmd := exec.Command("reg", "delete",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", "WireGuide", "/f")
	sysexec.Hide(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "not found") {
		return err
	}
	return nil
}
