//go:build !linux

package tunnel

import (
	"fmt"
	"github.com/korjwl1/wireguide/internal/config"
	"runtime"
)

func defaultKernelLinkBackend() (kernelLinkBackend, error) {
	return nil, fmt.Errorf("rtnetlink is not available on %s", runtime.GOOS)
}

func newKernelEngineWithDataDir(cfg, resolved *config.WireGuardConfig, resolvedEndpointIPs, resolvedEndpoints []string, _ string) (*Engine, error) {
	return newKernelEngine(cfg, resolved, resolvedEndpointIPs, resolvedEndpoints)
}
