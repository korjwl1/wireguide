//go:build windows

package tunnel

// kernelBackendSupported reports whether this build ships a kernel data
// plane. Windows uses the official WireGuardNT driver through wireguard.dll.
func kernelBackendSupported() bool { return true }
