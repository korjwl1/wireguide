package tunnel

import (
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// routeGuardBind pauses outer UDP sends during macOS endpoint route
// replacement. Changing blackhole flags requires delete/add on Darwin;
// the send gate makes that interval safe without removing tunnel routes.
type routeGuardBind struct {
	conn.Bind
	mu      sync.RWMutex
	allowed bool
}

func (b *routeGuardBind) SetEndpointTrafficAllowed(allowed bool) {
	b.mu.Lock()
	b.allowed = allowed
	b.mu.Unlock()
}

func (b *routeGuardBind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if !b.allowed {
		return nil
	}
	return b.Bind.Send(bufs, endpoint)
}
