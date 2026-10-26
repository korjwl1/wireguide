//go:build !windows && !linux

package tunnel

// kernelBackendSupported reports whether this build ships a kernel data
// plane. Only Windows (WireGuardNT) and Linux (the in-kernel WireGuard
// module) have one.
func kernelBackendSupported() bool { return false }
