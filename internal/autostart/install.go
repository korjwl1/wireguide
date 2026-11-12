package autostart

import (
	"encoding/xml"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/korjwl1/wireguide/internal/atomicfile"
	"github.com/korjwl1/wireguide/internal/launchd"
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

// SyncAutostart brings an existing autostart entry up to date with the
// current template, so an upgrade picks up template changes (macOS:
// AssociatedBundleIdentifiers in the LaunchAgent) without the user toggling
// auto-start off and on. Callers invoke it only while auto-start is on.
//
// macOS only; elsewhere it is a no-op. It never creates a missing entry (the
// user may have removed the login item outside the app), and it only acts for
// a binary inside an app bundle, so running a development build never points
// the login item at a build directory. It reports whether it rewrote the file.
func SyncAutostart(appPath string) (bool, error) {
	if runtime.GOOS != "darwin" {
		return false, nil
	}
	if !strings.Contains(appPath, ".app/Contents/MacOS/") {
		return false, nil
	}
	path, err := macAutostartPath()
	if err != nil {
		return false, err
	}
	return syncMacAutostartFile(path, appPath)
}

// syncMacAutostartFile migrates the LaunchAgent at path to the current
// template, but only when the file is byte-for-byte a login-item plist that an
// earlier WireGuide release generated for this very appPath. Anything else is
// the user's and is left untouched: a customised plist (extra keys, a wrapper
// executable, Program, comments), a file for another install (the user
// installed elsewhere, or this copy runs from a DMG or a translocated path),
// one already current, or one that is unreadable or not XML. Only toggling
// auto-start retargets or replaces such a file.
func syncMacAutostartFile(path, appPath string) (bool, error) {
	cur, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	want, err := renderMacAutostart(appPath)
	if err != nil {
		return false, err
	}
	if string(cur) == want {
		return false, nil
	}
	legacy, err := legacyMacAutostartPlists(appPath)
	if err != nil {
		return false, err
	}
	recognised := false
	for _, l := range legacy {
		if string(cur) == l {
			recognised = true
			break
		}
	}
	if !recognised {
		slog.Debug("autostart: LaunchAgent is not a recognised WireGuide template; leaving it as is", "path", path)
		return false, nil
	}
	// Atomic: a crash mid-write must not leave a truncated login-item plist.
	if err := atomicfile.WriteFile(path, []byte(want), 0644); err != nil {
		return false, err
	}
	return true, nil
}

// legacyMacAutostartPlists renders, for appPath, every login-item plist that
// earlier WireGuide releases generated, oldest first. They are the only files
// syncMacAutostartFile will migrate. Keep each renderer frozen: it must
// reproduce what that release wrote, byte for byte.
func legacyMacAutostartPlists(appPath string) ([]string, error) {
	var esc strings.Builder
	if err := xml.EscapeText(&esc, []byte(appPath)); err != nil {
		return nil, fmt.Errorf("xml-escape app path: %w", err)
	}
	return []string{
		// First release: appPath was written unescaped and the plist carried
		// LSUIElement.
		legacyMacAutostartPlistLSUIElement(appPath),
		// Later releases: appPath XML-escaped, no LSUIElement, no
		// AssociatedBundleIdentifiers.
		legacyMacAutostartPlistEscaped(esc.String()),
	}, nil
}

func legacyMacAutostartPlistLSUIElement(appPath string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
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
}

func legacyMacAutostartPlistEscaped(safeAppPath string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
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
}

// --- macOS: LaunchAgent ---

func macAutostartPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, "Library", "LaunchAgents", "com.wireguide.gui.plist"), nil
}

func installMacAutostart(appPath string) error {
	path, err := macAutostartPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("creating LaunchAgents dir: %w", err)
	}
	plist, err := renderMacAutostart(appPath)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(plist), 0644)
}

// renderMacAutostart XML-escapes appPath and renders the LaunchAgent.
func renderMacAutostart(appPath string) (string, error) {
	// XML-escape appPath to prevent plist injection from special characters.
	// xml.EscapeText returning an error means the escaping itself failed
	// (extremely rare — only from the io.Writer surface) and the buffer
	// may contain partial unescaped bytes. We MUST refuse to write the
	// plist in that case, otherwise an attacker who controls the path
	// could inject `</string>...<key>...` and modify our plist.
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(appPath)); err != nil {
		return "", fmt.Errorf("xml-escape app path: %w", err)
	}
	return macAutostartPlist(b.String()), nil
}

// macAutostartPlist renders the GUI LaunchAgent. safeAppPath must already be
// XML-escaped. AssociatedBundleIdentifiers attributes the login item to the
// WireGuide app in System Settings > Login Items & Extensions.
func macAutostartPlist(safeAppPath string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.wireguide.gui</string>
    <key>AssociatedBundleIdentifiers</key>
    <array>
        <string>%s</string>
    </array>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
`, launchd.AppBundleID, safeAppPath)
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
