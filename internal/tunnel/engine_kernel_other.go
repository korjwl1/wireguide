//go:build !windows && !linux

package tunnel

import (
	"fmt"
	"runtime"

	"github.com/korjwl1/wireguide/internal/config"
)

// newKernelEngine is unreachable in practice: BackendKernel.Supported()
// rejects the backend before construction on platforms without one. The
// symbol exists so the common engine.go path compiles everywhere.
func newKernelEngine(_ *config.WireGuardConfig, _ *config.WireGuardConfig, _, _ []string) (*Engine, error) {
	return nil, fmt.Errorf("kernel WireGuard backend is not available on %s", runtime.GOOS)
}
