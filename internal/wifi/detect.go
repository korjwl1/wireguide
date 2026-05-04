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
	// Use CoreWLAN (CWWiFiClient) instead of the `networksetup` shell command.
	// CoreWLAN registers the process with CoreLocation so WireGuide appears in
	// System Settings → Privacy & Security → Location Services and the user
	// can grant SSID access. networksetup never triggers that prompt.
	ssid := currentSSIDCoreWLAN()
	if ssid == "" {
		logLocationHintOnce()
	}
	return ssid
}

// discoverWiFiInterface finds the BSD interface name for the Wi-Fi hardware
// port. Tries CoreWLAN first (fast, no subprocess), falls back to parsing
// `networksetup -listallhardwareports` for edge cases. Returns "" on machines
// without Wi-Fi.
func discoverWiFiInterface() string {
	if name := wifiInterfaceNameCoreWLAN(); name != "" {
		return name
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "networksetup", "-listallhardwareports").CombinedOutput()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if strings.Contains(line, "Wi-Fi") || strings.Contains(line, "AirPort") {
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

// SSIDPermissionStatus describes whether the process can read the current SSID.
type SSIDPermissionStatus struct {
	HasWifi       bool `json:"has_wifi"`       // Wi-Fi hardware found
	HasPermission bool `json:"has_permission"` // SSID access granted (or no WiFi to check)
}

// CheckSSIDPermission returns whether the process can read the current SSID.
// On macOS 14+, SSID access requires Location Services permission. We detect
// the "permission denied" case by checking if the WiFi interface has an IP
// (we're connected) but networksetup still returns "not associated".
func CheckSSIDPermission() SSIDPermissionStatus {
	if runtime.GOOS != "darwin" {
		return SSIDPermissionStatus{HasWifi: false, HasPermission: true}
	}
	iface := discoverWiFiInterface()
	if iface == "" {
		return SSIDPermissionStatus{HasWifi: false, HasPermission: true}
	}
	// If we can read a non-empty SSID, permission is clearly granted.
	if CurrentSSID() != "" {
		return SSIDPermissionStatus{HasWifi: true, HasPermission: true}
	}
	// SSID is empty — could be "not on WiFi" or "permission denied".
	// Check if the interface has an IP: if yes, we're connected but can't
	// read the SSID → permission denied.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ipconfig", "getifaddr", iface).Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		// Not connected to WiFi — permission state is unknown but irrelevant.
		return SSIDPermissionStatus{HasWifi: true, HasPermission: true}
	}
	// Connected but can't see SSID → permission denied.
	return SSIDPermissionStatus{HasWifi: true, HasPermission: false}
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
