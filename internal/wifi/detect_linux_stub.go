//go:build !linux

package wifi

// startLinuxDBusWatcher is a no-op on non-Linux platforms. The Linux build
// uses NetworkManager's DBus DeviceStateChanged signal to react to SSID
// changes instantly; on other OSes the wifi.Monitor's per-platform
// detection (CoreWLAN events on macOS, Wlanapi notifications on Windows)
// covers the same ground.
func startLinuxDBusWatcher(onChange func()) (stop func()) {
	return func() {}
}
