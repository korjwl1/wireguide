//go:build !windows

package tunnel

import (
	"fmt"
	"runtime"

	"github.com/korjwl1/wireguide/internal/config"
)

// newKernelEngine is unreachable in practice: BackendKernel.Supported()
// rejects the backend before construction on non-Windows. The symbol exists
// so the common engine.go path compiles on every platform.
func newKernelEngine(_ *config.WireGuardConfig, _ *config.WireGuardConfig, _, _ []string) (*Engine, error) {
	return nil, fmt.Errorf("kernel WireGuard backend is not available on %s", runtime.GOOS)
}
