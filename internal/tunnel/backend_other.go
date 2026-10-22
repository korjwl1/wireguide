//go:build !windows

package tunnel

// kernelBackendSupported reports whether this build ships a kernel data
// plane. Only Windows has an embeddable kernel WireGuard implementation.
func kernelBackendSupported() bool { return false }
