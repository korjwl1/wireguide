//go:build !darwin

package wifi

import "errors"

func currentSSIDCoreWLAN() string       { return "" }
func wifiInterfaceNameCoreWLAN() string { return "" }
func RequestLocationAuthorization()     {}

// StartCoreWLANSSIDMonitor / StopCoreWLANSSIDMonitor are macOS-only.
// On Linux / Windows the wifi monitor falls back to its polling path.
func StartCoreWLANSSIDMonitor() (<-chan string, error) {
	return nil, errors.New("CoreWLAN SSID monitor not available on this platform")
}

func StopCoreWLANSSIDMonitor() {}
