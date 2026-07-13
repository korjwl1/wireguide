//go:build !darwin && !linux

package wifi

// GatewayMAC is not yet implemented on this platform (Windows). The
// "network" (gateway-fingerprint) Automation condition therefore never
// matches here; subnet and SSID conditions still work. A Windows
// implementation (GetIpNetTable2 via iphlpapi) is a follow-up.
func GatewayMAC() string { return "" }
