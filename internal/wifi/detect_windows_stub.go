//go:build !windows

package wifi

// startWindowsWlanWatcher is a no-op on non-Windows platforms. The Windows
// build uses wlanapi's WlanRegisterNotification to react instantly to SSID
// changes; the per-OS poll handles the same role elsewhere.
func startWindowsWlanWatcher(onChange func()) (stop func()) {
	return func() {}
}
