//go:build linux

package tunnel

// kernelBackendSupported reports whether this build ships a kernel data
// plane. Linux uses the in-kernel WireGuard module through rtnetlink.
func kernelBackendSupported() bool { return true }
