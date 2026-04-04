// Package wifi provides WiFi SSID detection and auto-connect rules.
package wifi

import (
	"os/exec"
	"runtime"
	"strings"
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
	out, err := exec.Command("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I").CombinedOutput()
	if err != nil {
		// Fallback for newer macOS
		out, err = exec.Command("networksetup", "-getairportnetwork", "en0").CombinedOutput()
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

func detectLinux() string {
	out, err := exec.Command("nmcli", "-t", "-f", "active,ssid", "dev", "wifi").CombinedOutput()
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

func detectWindows() string {
	out, err := exec.Command("netsh", "wlan", "show", "interfaces").CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SSID") && !strings.HasPrefix(line, "BSSID") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
