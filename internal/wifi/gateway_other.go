//go:build !darwin && !linux && !windows

package wifi

// GatewayMAC is only implemented on darwin/linux/windows; other
// platforms return "" (the "network" Automation condition never matches
// there, but subnet/SSID conditions still work).
func GatewayMAC() string { return "" }
