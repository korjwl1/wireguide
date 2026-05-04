// Package wifi provides WiFi SSID detection and auto-connect rules.
package wifi

import (
	"context"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// locationHintOnce ensures we log the macOS Location-permission hint
// at most once per helper lifetime. Without this guard the helper
// log fills with the same message every 5s if the user denied access.
var locationHintOnce sync.Once

func logLocationHintOnce() {
	locationHintOnce.Do(func() {
		slog.Warn("CurrentSSID returned empty: macOS reports 'not associated' " +
			"— Wi-Fi rules require Location Services permission. " +
			"Grant it in System Settings → Privacy & Security → Location Services → System Services.")
	})
}

// CurrentSSID returns the currently connected WiFi SSID, or "" if not connected.
func CurrentSSID() string {
	switch runtime.GOOS {
	case "darwin":
		return detectDarwin()
	case "linux":
		return detectLinux()
	case "windows":
		return detectWindows()
	}
	return ""
}

func detectDarwin() string {
	// The PrivateFrameworks `airport` binary was removed in macOS 15
	// (Sequoia) and stopped reporting SSIDs reliably in 14.4 once Apple
	// gated the API behind Location Services. networksetup is the
	// supported path on every macOS we still target — drop the airport
	// shell-out so we don't burn ~5s waiting for a binary that's gone.
	wifiIface := discoverWiFiInterface()
	if wifiIface == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "networksetup", "-getairportnetwork", wifiIface).CombinedOutput()
	if err != nil {
		return ""
	}
	// Output: "Current Wi-Fi Network: MySSID" on success, or
	// "You are not associated with an AirPort network." on
	// failure / Location-permission denied. The latter has no
	// ": " separator so we'll return "" — but we also log a
	// hint so users debugging "rules don't fire" know to check
	// Settings → Privacy → Location Services.
	s := strings.TrimSpace(string(out))
	if strings.Contains(s, "not associated") {
		logLocationHintOnce()
		return ""
	}
	if idx := strings.Index(s, ": "); idx >= 0 {
		return s[idx+2:]
	}
	return ""
}

// discoverWiFiInterface finds the BSD interface name for the Wi-Fi
// hardware port. Returns "" when no Wi-Fi port is found — the old
// behaviour of falling back to "en0" silently misled callers on
// Mac minis / desktops where en0 is Ethernet, producing empty SSID
// reads forever instead of a clear "no Wi-Fi here" signal.
func discoverWiFiInterface() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "networksetup", "-listallhardwareports").CombinedOutput()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if strings.Contains(line, "Wi-Fi") || strings.Contains(line, "AirPort") {
			// Next line should be "Device: en0" or similar
			if i+1 < len(lines) {
				parts := strings.SplitN(lines[i+1], ":", 2)
				if len(parts) == 2 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	}
	return ""
}

func detectLinux() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nmcli", "-t", "-f", "active,ssid", "dev", "wifi").CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "yes:") {
			return strings.TrimPrefix(line, "yes:")
		}
	}
	return ""
}

// KnownSSIDs returns the system's saved wireless network names so the
// GUI can show a picker for Wi-Fi auto-connect rules instead of making
// the user retype every SSID. Empty slice on platforms we haven't wired
// up yet — the picker degrades to manual input only.
func KnownSSIDs() []string {
	switch runtime.GOOS {
	case "darwin":
		return knownSSIDsDarwin()
	}
	return nil
}

func knownSSIDsDarwin() []string {
	iface := discoverWiFiInterface()
	if iface == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "networksetup", "-listpreferredwirelessnetworks", iface).CombinedOutput()
	if err != nil {
		return nil
	}
	// Output:
	//   Preferred networks on en0:
	//   <TAB>MyHomeWiFi
	//   <TAB>Office
	var result []string
	for i, line := range strings.Split(string(out), "\n") {
		if i == 0 {
			continue
		}
		s := strings.TrimSpace(line)
		if s == "" {
			continue
		}
		result = append(result, s)
	}
	return result
}

func detectWindows() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "netsh", "wlan", "show", "interfaces").CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		// Match "SSID" followed by optional spaces and a colon, but NOT
		// "SSID2", "BSSID", etc. The netsh output uses "SSID  : MyNetwork"
		// for the SSID field and "BSSID  : xx:xx:..." for the BSSID.
		if (strings.HasPrefix(trimmed, "SSID ") || strings.HasPrefix(trimmed, "SSID:")) && !strings.HasPrefix(trimmed, "BSSID") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
