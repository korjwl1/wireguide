// Package wifi provides WiFi SSID detection and auto-connect rules.
package wifi

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

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
	// macOS 14+: use system_profiler or airport
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I").CombinedOutput()
	if err != nil {
		// Fallback: discover the actual Wi-Fi interface dynamically instead
		// of hardcoding "en0" (which may be Ethernet on some Macs).
		wifiIface := discoverWiFiInterface()
		if wifiIface == "" {
			return ""
		}
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		out, err = exec.CommandContext(ctx2, "networksetup", "-getairportnetwork", wifiIface).CombinedOutput()
		if err != nil {
			return ""
		}
		// Output: "Current Wi-Fi Network: MySSID"
		s := strings.TrimSpace(string(out))
		if idx := strings.Index(s, ": "); idx >= 0 {
			return s[idx+2:]
		}
		return ""
	}
	// Parse airport -I output for SSID line
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SSID:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "SSID:"))
		}
	}
	return ""
}

// discoverWiFiInterface finds the BSD interface name for the Wi-Fi hardware port.
func discoverWiFiInterface() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "networksetup", "-listallhardwareports").CombinedOutput()
	if err != nil {
		return "en0" // fallback
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
	return "en0" // fallback
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
