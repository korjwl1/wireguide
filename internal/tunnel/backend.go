package tunnel

import "time"

// BackendKind selects the WireGuard implementation that carries tunnel
// traffic. The userspace backend is wireguard-go with a platform TUN
// adapter (Wintun on Windows). The kernel backend is the platform's
// in-kernel implementation (WireGuardNT on Windows).
type BackendKind string

const (
	BackendUserspace BackendKind = "userspace"
	BackendKernel    BackendKind = "kernel"
)

// ParseBackendKind maps a persisted setting to a known backend. Unknown or
// empty values fall back to userspace, so an old or hand-edited settings
// file cannot select an implementation this build does not support.
func ParseBackendKind(value string) BackendKind {
	if BackendKind(value) == BackendKernel {
		return BackendKernel
	}
	return BackendUserspace
}

func (k BackendKind) String() string { return string(k) }

// Supported reports whether this build can create the requested backend.
// Userspace is available everywhere; the kernel backend is Windows-only.
func (k BackendKind) Supported() bool {
	switch k {
	case BackendKernel:
		return kernelBackendSupported()
	case BackendUserspace:
		return true
	}
	return false
}

// kernelBackend is the platform kernel data plane. It is nil for userspace
// engines and for builds without a kernel backend. Callers go through Engine
// so manager, status, and network code stay backend-agnostic.
type kernelBackend interface {
	Start() error
	Close() error
	Status(tunnelName string, connectedAt time.Time) (*ConnectionStatus, error)
	CurrentEndpointIPs() ([]string, error)
}
