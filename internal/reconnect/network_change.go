package reconnect

import "time"

// A suppressed final observation must still fire once the cooldown expires,
// even when no further interface change arrives.
type interfaceChangeGate struct {
	initialized bool
	lastIface   string
	lastFire    time.Time
	pending     bool
	cooldown    time.Duration
}

func (g *interfaceChangeGate) observe(iface string, now time.Time) bool {
	if !g.initialized {
		g.initialized, g.lastIface = true, iface
		return false
	}
	if iface != g.lastIface {
		g.lastIface, g.pending = iface, true
	}
	if !g.pending || (!g.lastFire.IsZero() && now.Sub(g.lastFire) < g.cooldown) {
		return false
	}
	g.pending, g.lastFire = false, now
	return true
}
